package main

import "testing"

func TestUbusCallGrantsNameAnObjectAndAMethod(t *testing.T) {
	fakeUbus(t, "{}")
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'ubus_call'\n\tlist scopes 'network.*'\n")

	if out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "network", "method": "reload"}); isErr {
		t.Errorf("object network, method reload, is covered by network.*: %q", out)
	}
	if out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "network.interface.lan", "method": "status"}); !isErr {
		t.Errorf("network.* reached another object's method: %q", out)
	}
	if out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "network", "method": "interface.lan.status"}); !isErr {
		t.Errorf("a method name with dots borrowed the grant for another object: %q", out)
	}
}

func TestUbusCallRefusesWhatIsNotAPlainObjectAndMethod(t *testing.T) {
	fakeUbus(t, "{}")
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'ubus_call'\n\tlist scopes '*'\n")

	for _, c := range []struct{ object, method string }{
		{"-s", "board"},
		{"system", "-x"},
		{"sys tem", "board"},
		{"system", "a.b"},
		{"system", "bo/ard"},
	} {
		if out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": c.object, "method": c.method}); !isErr {
			t.Errorf("not a plain pair, ran under the wildcard grant: %q %q: %q", c.object, c.method, out)
		}
	}
	if out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "system", "method": "board"}); isErr {
		t.Errorf("a plain pair under the wildcard grant was refused: %q", out)
	}
}

func TestUbusCallWildcardMethodStaysOnItsObject(t *testing.T) {
	fakeUbus(t, "{}")
	s, _ := newToolRig(t, "config policy\n\toption client 'a'\n\tlist tools 'ubus_call'\n\tlist scopes 'iwinfo.*'\n")

	if out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "iwinfo", "method": "devices"}); isErr {
		t.Errorf("iwinfo.* did not cover iwinfo.devices: %q", out)
	}
	if out, isErr := callTool(t, s, "a", "ubus_call", map[string]any{"object": "iwinfo.devices", "method": "x"}); !isErr {
		t.Errorf("iwinfo.* covered a different object, iwinfo.devices: %q", out)
	}
}
