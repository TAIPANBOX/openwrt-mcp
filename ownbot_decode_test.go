package main

// What the bot reads from Telegram, decoded strictly: hostile answers, a sweep of mutated ones, a fuzz
// target, and the reading of a factor out of a message.

import (
	"encoding/json"
	"math/rand"
	"strings"
	"testing"
)

const sampleUpdates = `{"ok":true,"result":[
{"update_id":101,"message":{"message_id":7,"from":{"id":4242,"is_bot":false},"chat":{"id":4242,"type":"private"},"date":1,"text":"1234 567890"}},
{"update_id":102,"callback_query":{"id":"cb1","from":{"id":4242,"is_bot":false},"data":"a:KQWPT:0123456789abcdef","message":{"message_id":8,"from":{"id":999,"is_bot":true},"chat":{"id":4242,"type":"private"},"date":1}}}
]}`

// decodeAnswer is getUpdates as the client reads it: the envelope, then the updates.
func decodeAnswer(b []byte) ([]tgUpdate, error) {
	var raw json.RawMessage
	if err := decodeTelegramAnswer("getUpdates", 200, b, &raw); err != nil {
		return nil, err
	}
	return decodeUpdates(raw)
}

func TestTelegramAnswersAreReadWithinTheirBounds(t *testing.T) {
	ups, err := decodeAnswer([]byte(sampleUpdates))
	if err != nil || len(ups) != 2 || ups[0].Bad || ups[1].Bad || ups[0].Message.Text != "1234 567890" ||
		ups[1].CallbackQuery.Data != "a:KQWPT:0123456789abcdef" {
		t.Fatalf("a sound answer did not read: %v %+v", err, ups)
	}
	for name, body := range map[string]string{
		"not JSON":            `<html>`,
		"refused":             `{"ok":false,"error_code":401,"description":"Unauthorized"}`,
		"no result":           `{"ok":true}`,
		"a result not a list": `{"ok":true,"result":{"update_id":1}}`,
		"more than asked for": `{"ok":true,"result":[` + strings.Repeat(`{"update_id":1},`, maxUpdatesPerPoll) + `{"update_id":1}]}`,
	} {
		if _, err := decodeAnswer([]byte(body)); err == nil {
			t.Errorf("%s: read as updates", name)
		}
	}
	long := strings.Repeat("x", maxTelegramText+1)
	for name, u := range map[string]string{
		"no id":                 `{"message":{"message_id":7,"from":{"id":1},"chat":{"id":1,"type":"private"},"text":"a"}}`,
		"both kinds":            `{"update_id":5,"message":{"message_id":7,"chat":{"id":1,"type":"private"}},"callback_query":{"id":"c","from":{"id":1},"message":{"message_id":7,"chat":{"id":1,"type":"private"}}}}`,
		"neither kind":          `{"update_id":5}`,
		"an unknown chat":       `{"update_id":5,"message":{"message_id":7,"from":{"id":1},"chat":{"id":1,"type":"secret"},"text":"a"}}`,
		"a text over 4096":      `{"update_id":5,"message":{"message_id":7,"from":{"id":1},"chat":{"id":1,"type":"private"},"text":"` + long + `"}}`,
		"button data over 64":   `{"update_id":5,"callback_query":{"id":"c","from":{"id":1},"data":"` + strings.Repeat("a", 65) + `","message":{"message_id":7,"chat":{"id":1,"type":"private"}}}}`,
		"a tap on no message":   `{"update_id":5,"callback_query":{"id":"c","from":{"id":1},"data":"a"}}`,
		"an id of another type": `{"update_id":5,"message":{"message_id":"7","from":{"id":1},"chat":{"id":1,"type":"private"},"text":"a"}}`,
	} {
		ups, err := decodeAnswer([]byte(`{"ok":true,"result":[` + u + `]}`))
		if err != nil || len(ups) != 1 || !ups[0].Bad {
			t.Errorf("%s: not marked bad: %v %+v", name, err, ups)
		}
	}
}

// Every update decodeUpdates hands on whole is one checkUpdate accepts, whatever the bytes were.
func checkDecoded(t *testing.T, b []byte) {
	ups, err := decodeAnswer(b)
	if err != nil {
		return
	}
	if len(ups) > maxUpdatesPerPoll {
		t.Fatalf("%d updates handed on", len(ups))
	}
	for _, u := range ups {
		if !u.Bad && !checkUpdate(u) {
			t.Fatalf("an update out of bounds was handed on: %+v", u)
		}
		if !u.Bad && u.Message != nil && len(u.Message.Text) > maxTelegramText {
			t.Fatal("a text over its bound was handed on")
		}
	}
}

// A sweep of 200 seeds of mutated answers through the decoder: nothing panics, and nothing out of
// bounds is handed on.
func TestTelegramDecoderSurvivesASweepOfHostileAnswers(t *testing.T) {
	base := []byte(sampleUpdates)
	for seed := int64(1); seed <= 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		b := append([]byte(nil), base...)
		for i := 0; i < 1+rng.Intn(8); i++ {
			switch rng.Intn(4) {
			case 0:
				b[rng.Intn(len(b))] = byte(rng.Intn(256))
			case 1:
				p := rng.Intn(len(b))
				b = append(b[:p], b[min(len(b), p+1+rng.Intn(10)):]...)
			case 2:
				p := rng.Intn(len(b))
				b = append(b[:p], append([]byte(`"x":[1,{"y":null}],`), b[p:]...)...)
			case 3:
				b = []byte(strings.Replace(string(b), "4242", []string{"-1", "0", "1e99", `"4242"`, "4243"}[rng.Intn(5)], 1))
			}
			if len(b) == 0 {
				b = []byte("{")
			}
		}
		checkDecoded(t, b)
	}
}

func FuzzTelegramUpdates(f *testing.F) {
	f.Add([]byte(sampleUpdates))
	f.Add([]byte(`{"ok":true,"result":[]}`))
	f.Add([]byte(`{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"chat":{"id":1,"type":"group"},"text":"/start x"}}]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		checkDecoded(t, b)
		ups, err := decodeAnswer(b)
		if err != nil {
			return
		}
		for _, u := range ups {
			if u.Bad || u.Message == nil {
				continue
			}
			// What the bot reads from a message is bounded whatever the text.
			if f, ok := parseFactor(u.Message.Text, factorPINTOTP); ok && (len(f.PIN) < 4 || len(f.PIN) > 8 || len(f.Code) != 6) {
				t.Fatalf("a factor of the wrong shape was read: %+v", f)
			}
			if c, ok := startCode(u.Message.Text); ok && !bindCodeShape.MatchString(c) {
				t.Fatalf("a binding code of the wrong shape was read: %q", c)
			}
		}
	})
}

// A factor is read from a message as the owner types it on a phone: digits in any script, a space or
// a comma between the PIN and the code; anything else is not a factor.
func TestAFactorIsReadAsTheOwnerTypesIt(t *testing.T) {
	for _, c := range []struct {
		text, factor string
		pin, code    string
		ok           bool
	}{
		{"1234 567890", factorPINTOTP, "1234", "567890", true},
		{" 12345678,567890 ", factorPINTOTP, "12345678", "567890", true},
		{"١٢٣٤ ٥٦٧٨٩٠", factorPINTOTP, "1234", "567890", true}, // Arabic-Indic
		{"１２３４ ５６７８９０", factorPINTOTP, "1234", "567890", true}, // full-width
		{"1234567890", factorPINTOTP, "", "", false},
		{"123 567890", factorPINTOTP, "", "", false},
		{"1234 56789", factorPINTOTP, "", "", false},
		{"1234 567890 1", factorPINTOTP, "", "", false},
		{"pin 1234 567890", factorPINTOTP, "", "", false},
		{"567890", factorTOTP, "", "567890", true},
		{"1234 567890", factorTOTP, "", "", false},
		{"4821", factorPIN, "4821", "", true},
		{"4821 567890", factorPIN, "", "", false},
	} {
		f, ok := parseFactor(c.text, c.factor)
		if ok != c.ok || f.PIN != c.pin || f.Code != c.code {
			t.Errorf("%q as %s: got %+v %v", c.text, c.factor, f, ok)
		}
	}
	for text, want := range map[string]bool{"1234": true, "1234 567890": true, "/unlock 1234": false, "hi 1234": false, "": false} {
		if looksLikeFactor(text) != want {
			t.Errorf("looksLikeFactor(%q) is not %v", text, want)
		}
	}
	if !carriesFactor("/unlock 1234 567890") || !carriesFactor("/UNLOCK@router_bot 1234") || carriesFactor("/lock") {
		t.Error("an /unlock is not taken as carrying a factor, or a /lock is")
	}
}
