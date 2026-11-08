#!/usr/bin/env python3
"""mutate-split.py -- break the split of the daemon on purpose, and require a named test to notice.

Each mutant below is a change to the code of the split (helper.go, frontend.go, server.go, the
listener's confinement) that would make a wrong answer silent: the helper serving a peer that is not
the listener, taking an operation or a tool off its list, believing a name instead of resolving a
token, reading a frame of any size or shape, or the listener running as root, holding a capability or
starting a program. For each one the script copies the repository, applies the mutant, runs the test
named beside it, and requires that test to FAIL. It first runs every named test on the unmutated code
and requires each to PASS. A mutant whose text is no longer in its file is a failure, not a skip.

The decisions the helper makes on a call (the policy, the owner's rules, the second factor, held
changes, the throttle) are the gate's, and scripts/mutate-held.py breaks those.

    ./scripts/mutate-split.py            every mutant
    ./scripts/mutate-split.py 3 7        just those, by number
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# (what it breaks, file, the text, what it becomes, the test that must go red)
MUTANTS = [
    ("the helper serves any peer", "helper.go",
     "if err != nil || uid != h.parserUID {", "if err != nil {", "TestHelperServesOnlyTheListenersUID"),
    ("a peer whose uid cannot be read is served", "helper.go",
     "if err != nil || uid != h.parserUID {", "if uid != h.parserUID {", "TestHelperRefusesAPeerWhoseUIDCannotBeRead"),
    ("the helper takes a token as the client's name", "server.go",
     "\tclient, ok := s.tokens.Resolve(strings.TrimSpace(token))\n\tif !ok {\n\t\ts.badToken(\"the listener\")",
     "\tclient, ok := token, true\n\tif !ok {\n\t\ts.badToken(\"the listener\")",
     "TestHelperResolvesTheTokenItselfOnEveryCall"),
    ("a call with no token runs as no client", "server.go",
     "\tif !ok {\n\t\ts.badToken(\"the listener\")", "\tif !ok && token != \"\" {\n\t\ts.badToken(\"the listener\")",
     "TestHelperResolvesTheTokenItselfOnEveryCall"),
    ("a bad token at the door is not written", "server.go",
     "\tif !ok {\n\t\ts.badToken(remote)\n\t}", "\t_ = remote", "TestTheListenerRunsToolsOnlyThroughTheHelper"),
    ("an operation off the list is taken", "helper.go",
     'return r, fmt.Errorf("%w: %q is not an operation", errNotARequest, r.Op)', "return r, nil",
     "TestHelperDecoderSurvivesASweepOfHostileFrames"),
    ("a tool off the list is taken", "helper.go",
     "if _, ok := toolByName(r.Tool); !ok {", "if false {", "TestHelperRefusesAnActionOffTheList"),
    ("an input that is not an object is taken", "helper.go",
     "if t := bytes.TrimLeft(r.Input, \" \\t\\r\\n\"); len(t) == 0 || t[0] != '{' {",
     "if t := bytes.TrimLeft(r.Input, \" \\t\\r\\n\"); false && (len(t) == 0 || t[0] != '{') {",
     "TestHelperDecodesEveryFrameStrictly"),
    ("a field the type lacks is ignored", "tools.go", "\tdec.DisallowUnknownFields()\n", "",
     "TestHelperRefusesAnActionOffTheList"),
    ("data after the object is taken", "tools.go", "\tif _, err := dec.Token(); err != io.EOF {",
     "\tif _, err := dec.Token(); false && err != io.EOF {",
     "TestHelperDecodesEveryFrameStrictly"),
    ("another protocol version is taken", "helper.go", "if r.V != helperProtoVersion {", "if false {",
     "TestHelperDecodesEveryFrameStrictly"),
    ("a field over its bound is taken", "helper.go",
     "if len(r.Token) > maxTokenLen || len(r.Remote) > maxRemoteLen || len(r.Tool) > maxToolNameLen {", "if false {",
     "TestHelperDecodesEveryFrameStrictly"),
    ("a field an operation does not take is taken", "helper.go",
     'return fmt.Errorf("%w: %s takes no such field", errNotARequest, r.Op)', "return nil",
     "TestHelperDecodesEveryFrameStrictly"),
    ("a frame of any size is read", "helper.go", "if size == 0 || size > uint32(max) {", "if size == 0 {",
     "TestHelperBoundsItsFrames"),
    ("requests at once are unbounded", "helper.go",
     '\tdefault:\n\t\th.reply(c, "", helperResponse{Refusal: "busy: too many requests at once"})\n\t\treturn\n', "",
     "TestHelperIsBusyRatherThanUnbounded"),
    ("the listener passes an oversize token on", "frontend.go", "\tif len(raw) > maxTokenLen {", "\tif false {",
     "TestTheListenerSendsNoOversizeToken"),
    ("the listener answers for an absent helper", "frontend.go",
     "\t\tpersisted, err := f.b.health()\n\t\tif err != nil {", "\t\tpersisted, err := f.b.health()\n\t\tif err != nil && false {",
     "TestTheListenerWithoutItsHelperRunsNothing"),
    ("an error's text is not bounded", "tools.go", "\t\t\treturn boundText(text), true\n", "\t\t\treturn text, true\n",
     "TestAnErrorsTextIsBoundedLikeAnAnswer"),
    ("an answer too large is not replaced by the short one", "helper.go",
     "\tif err == nil && len(b) > maxResponseFrame {\n", "\tif false {\n", "TestAnAnswerTooLargeToSendSaysTheCallRan"),
    ("an answer lost after the call was sent reads as nothing run", "helper.go",
     'return helperResponse{}, fmt.Errorf("%w: the request was sent and no answer came (%v)", errOutcomeUnknown, err)',
     'return helperResponse{}, fmt.Errorf("the request was sent and no answer came (%v)", err)',
     "TestAnAnswerLostAfterTheCallWasSentIsAnUnknownOutcome"),
    ("the listener tells the agent nothing ran when the outcome is unknown", "frontend.go",
     "\t\tif errors.Is(err, errOutcomeUnknown) {\n", "\t\tif false && errors.Is(err, errOutcomeUnknown) {\n",
     "TestAnAnswerLostAfterTheCallWasSentIsAnUnknownOutcome"),
    ("a lost answer is not written in the audit log", "helper.go",
     '\tif err := h.reply(c, req.Op, h.dispatch(ctx, req)); err != nil && req.Op == "call" {\n',
     '\tif err := h.reply(c, req.Op, h.dispatch(ctx, req)); err != nil && false {\n',
     "TestAnAnswerThatDidNotReachTheListenerIsAudited"),
    ("the listener runs as root", "seccomp_filter.go", "\tif uid == 0 || euid == 0 {", "\tif false {",
     "TestTheListenerRefusesRootAndAnyCapability"),
    ("the listener's account may keep a bounding set", "seccomp_filter.go",
     '\t\twant = append(want, "CapBnd")\n', "", "TestTheListenerRefusesRootAndAnyCapability"),
    ("the listener may hold an effective capability", "seccomp_filter.go",
     'want := []string{"CapEff", "CapPrm", "CapAmb"}', 'want := []string{"CapPrm", "CapAmb"}',
     "TestTheListenerRefusesRootAndAnyCapability"),
    ("the listener's account may run without no_new_privs", "seccomp_filter.go",
     "\t\tif err := checkNoNewPrivs(status); err != nil {\n\t\t\treturn \"\", err\n\t\t}\n", "",
     "TestTheListenerRefusesRootAndAnyCapability"),
    ("the listener's filter lets it start programs", "seccomp_linux.go",
     "return confineSeccompWith([]uint32{unix.SYS_EXECVE, unix.SYS_EXECVEAT})", "return confineSeccompWith(nil)",
     "TestTheListenersFilterStartsNoProgram"),
    ("the socket's directory open to every account", "helper.go", "\tmode := os.FileMode(0o700)\n",
     "\tmode := os.FileMode(0o755)\n", "TestListenerSocketIsItsOwn"),
    ("the socket open to every account", "helper.go", "\tsock := os.FileMode(0o600)\n",
     "\tsock := os.FileMode(0o666)\n", "TestListenerSocketIsItsOwn"),
]


def go_test(where, tests):
    pattern = "^(" + "|".join(sorted(set(tests))) + ")$"
    p = subprocess.run(["go", "test", "-count=1", "-run", pattern, "."], cwd=where, capture_output=True, text=True,
                       timeout=600)
    return p.returncode, p.stdout + p.stderr


def copy_repo():
    tmp = tempfile.mkdtemp(prefix="mutate-split-")
    dst = os.path.join(tmp, "repo")
    shutil.copytree(REPO, dst, ignore=shutil.ignore_patterns(".git", "*.ipk", "*.apk", "openwrt-mcp.amd64", "openwrt-mcp.arm64"))
    return tmp, dst


def main(argv):
    picked = [int(a) for a in argv] if argv else list(range(1, len(MUTANTS) + 1))
    if not MUTANTS:
        print("FAIL: no mutants: measured nothing")
        return 1
    tests = [MUTANTS[i - 1][4] for i in picked]
    code, out = go_test(REPO, tests)
    if code != 0:
        print(out[-3000:])
        print("FAIL: the tests the mutants are judged by are not green on the unmutated code")
        return 1
    bad = 0
    for i in picked:
        what, path, old, new, test = MUTANTS[i - 1]
        tmp, dst = copy_repo()
        try:
            f = os.path.join(dst, path)
            with open(f, encoding="utf-8") as fh:
                src = fh.read()
            if src.count(old) != 1:
                print(f"FAIL mutant {i} ({what}): its text is in {path} {src.count(old)} times, not once; "
                      "the code moved, so move the mutant")
                bad += 1
                continue
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(src.replace(old, new, 1))
            code, out = go_test(dst, [test])
            if code == 0:
                print(f"FAIL mutant {i} ({what}): {test} stayed green")
                bad += 1
            elif re.search(r"^--- FAIL: " + re.escape(test) + r"\b", out, re.M):
                print(f"caught mutant {i} ({what}): {test}")
            elif "build failed" in out or "[build failed]" in out or re.search(r"^# ", out, re.M):
                print(out[-1500:])
                print(f"FAIL mutant {i} ({what}): it does not compile, so it proves nothing")
                bad += 1
            else:
                print(out[-1500:])
                print(f"FAIL mutant {i} ({what}): red, but not in {test}")
                bad += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        print(f"FAIL: {bad} of {len(picked)} mutants were not caught by the test named for them")
        return 1
    print(f"mutate-split: {len(picked)} mutants, each caught by the test named for it")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
