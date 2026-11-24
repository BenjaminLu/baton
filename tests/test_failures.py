"""Failure modes under the boundary map (boundary-review.md §3).

verify.py's rules run in-process; the page's evidence-link rule runs under
Node; the rendered table runs in headless Chrome (each skipped when absent).
Run: python3 -m unittest discover -s tests
"""
import copy, html as htmlmod, json, re, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import verify  # noqa: E402
from verify import check_failures, safe_ref  # noqa: E402
from test_attacks import CHROME, on  # noqa: E402

NODE = shutil.which("node")
SHA = "3f9c2a1b7d4e5f60718293a4b5c6d7e8f9012345"
REF = f"https://github.com/example/notes-api/blob/{SHA}/push/worker.go#L40-L58"

HOSTILE = ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,<script>x</script>",
           " https://evil.example/a", "\u0001https://evil.example/a", "\thttps://evil.example/a",
           "https://evil.example/a b", "https://evil.example/\n", "http://plain.example/a",
           "//evil.example/a", "mailto:a@b.c", 'https://a"onmouseover="' + on("ref") + '"',
           "https://a/'x", "https://a/<b>", "java\u0000script:x", "\u007fhttps://evil.example",
           "http\u017f://evil.example/a", "https://github.com@evil.example/o/r/blob/abcdef1/x.py#L1",
           "https://evil.example\\@github.com/x",
           # host and path normalisation: each would open something other than what is shown
           f"https://github.com./o/r/blob/{SHA}/a.go#L1", f"https://github.com:443/o/r/blob/{SHA}/a.go#L1",
           f"https://github.com:0443/o/r/blob/{SHA}/a.go#L1", f"https://github%2ecom/o/r/blob/{SHA}/a.go#L1",
           f"https://\uff47ithub.com/o/r/blob/{SHA}/a.go#L1", f"https://github.com/o/r/blob/{SHA}/../main/a.go",
           f"https://github.com/o/r/blob/{SHA}/%2e%2e/main/a.go", f"https://github.com/o/r/blob/{SHA}\\..\\main/a.go",
           "https://evil.example/a/.", "https://.evil.example/a", "https://evil..example/a",
           # GitHub folds // and decodes %xx in the path
           f"https://github.com//evil/baton/blob/{SHA}/a.go#L1", f"https://github.com/evil//baton/blob/{SHA}/a.go#L1",
           f"https://github.com/o/r//blob/main/a.go#L1", "https://github.com/o/r/bl%6fb/main/a.go#L1",
           f"https://github.com/o/r/blob/{SHA}/a%2fb.go#L1", "https://docs.example.com/a//b",
           "https://raw.github.com/o/r/bl%6fb/a.go"]


def chain(heading):
    return {
        "kind": "chain", "heading": {"en": heading}, "tone": "warn",
        "nodes": [{"id": "api", "name": {"en": "API"}}, {"id": "worker", "name": {"en": "Push worker"}},
                  {"id": "fcm", "name": {"en": "FCM"}}],
        "before": {"hot": ["worker"], "sub": {"worker": "send()"},
                   "why": {"at": "worker", "text": {"en": "`UNREGISTERED` is retried like a 5xx"}},
                   "outcome": {"en": "the dead token is retried `5` times per message",
                               "hant": "失效的 token 每則訊息重試 `5` 次"}},
        "after": {"hot": ["worker"], "sub": {"worker": "send() + prune"},
                  "why": {"at": "worker", "text": {"en": "`UNREGISTERED` deletes the token"}},
                  "outcome": {"en": "the token row is deleted; next send skips it",
                              "hant": "token 那一列被刪掉；下次發送會跳過它"}},
        "proof": [{"type": "test", "label": {"en": "worker_test.go:88"}, "state": "verified"}],
    }


def legacy_failures():
    """Failure modes as packets wrote them before ids and the runbook: detect,
    impact and action on the map row itself."""
    return [
        {"at": "app>api", "mode": {"en": "API is down or times out"},
         "detect": {"en": "`api_5xx_ratio` alert > 2% for 5 min"},
         "impact": {"en": "the note does not save; the app shows Retry"},
         "action": {"en": "the app retries with backoff; page on-call if the alert holds"},
         "ref": f"https://github.com/example/notes-app/blob/{SHA}/sync/client.ts#L12-L30", "state": "handled"},
        {"at": "worker>fcm", "mode": {"en": "FCM returns `UNREGISTERED` for a token"},
         "detect": {"en": "`push_send_errors_total{code=\"UNREGISTERED\"}`"},
         "impact": {"en": "that phone never gets reminders"},
         "action": {"en": "delete the token; the app registers a new one on next launch"},
         "ref": REF, "state": "unhandled", "introduced": True, "finding": 1},
        {"at": "worker>fcm", "mode": {"en": "FCM answers 5xx or 429"},
         "detect": {"en": "`push_send_errors_total{code=\"UNAVAILABLE\"}`"},
         "impact": {"en": "reminders arrive late"},
         "action": {"en": "retry with exponential backoff, at most 5 times, honour Retry-After"},
         "ref": REF, "state": "handled"},
        {"at": "api>worker", "mode": {"en": "a job is delivered twice"},
         "impact": {"en": "the user gets the same reminder twice"},
         "action": {"en": "dedupe on job id before sending"}, "state": "unhandled"},
        {"at": "fcm", "mode": {"en": "the service-account key expires"},
         "detect": {"en": "`push_auth_failures_total` alert"},
         "impact": {"en": "no reminder reaches anyone"},
         "action": {"en": "rotate the key from the secrets store; page on-call"}, "state": "detected"},
    ]


IDS = ["api-down", "fcm-unregistered", "fcm-5xx", "job-twice", "fcm-key-expired"]


def failures():
    """The map rows: id, at, mode, state, evidence. Nothing else."""
    out = []
    for fid, f in zip(IDS, legacy_failures()):
        f = {k: v for k, v in f.items() if k not in ("detect", "impact", "action")}
        out.append(dict(f, id=fid))
    return out


def runbook():
    """The runbook: detect, impact, action, once each, keyed by failure id."""
    return [dict({k: f[k] for k in ("detect", "impact", "action") if k in f}, failure=fid)
            for fid, f in zip(IDS, legacy_failures())]


def packet(**boundary):
    b = {"kind": "boundary", "role": "boundary-review", "heading": {"en": "Where it can break"},
         "systems": [{"id": "app", "name": {"en": "Notes app"}, "kind": "client"},
                     {"id": "api", "name": {"en": "API"}}, {"id": "worker", "name": {"en": "Push worker"}},
                     {"id": "fcm", "name": {"en": "FCM"}, "kind": "external"}],
         "hops": {"0": "HTTPS", "1": "job", "2": "HTTP v1"},
         "findings": [{"n": 1, "at": "worker>fcm", "lens": "dependency", "tone": "warn",
                       "title": {"en": "dead tokens are retried forever"}, "card": "Dead tokens are retried"}],
         "failures": failures(), "runbook": runbook()}
    b.update(boundary)
    b = {k: v for k, v in b.items() if v is not None}
    return {"title": {"en": "failure modes"}, "sections": [chain("Dead tokens are retried"), b]}


def fail_problems(data, register="engineer"):
    return check_failures(data, register)[0]


def link_warnings(warns):
    return [w for w in warns if w.startswith("link ")]


def quiet(warns):
    """The "no signal today" warning: the gap is flagged, never failed."""
    return [w for w in warns if w.startswith("no signal today")]


class VerifyFailures(unittest.TestCase):
    def test_clean_packet_passes(self):
        probs, warns = check_failures(packet())
        self.assertEqual(probs, [])
        self.assertEqual(len(warns), 1, warns)          # job-twice has no signal today: flagged, not failed
        self.assertIn("job-twice", quiet(warns)[0])

    def test_missing_failures_fails_engineer_warns_eli5(self):
        p = packet(failures=None)
        probs, warns = check_failures(p, "engineer")
        self.assertEqual(len(probs), 1)
        self.assertIn("no `failures`", probs[0])
        probs, warns = check_failures(p, "eli5")
        self.assertEqual(probs, [])
        self.assertEqual(len(warns), 1)

    def test_empty_list_warns_per_uncovered_link(self):
        probs, warns = check_failures(packet(failures=[], runbook=[]))
        self.assertEqual(probs, [])
        self.assertEqual(sorted(re.search(r'link "([^"]+)"', w).group(1) for w in warns),
                         ["api>worker", "app>api", "worker>fcm"])

    def test_ok_line_silences_coverage_warning(self):
        p = packet(failures=[], runbook=None, findings=[], ok={"en": "UI-only change; nothing crosses a boundary"})
        p["sections"] = p["sections"][1:]
        self.assertEqual(check_failures(p), ([], []))

    def test_endpoint_row_covers_its_links(self):
        rows = [r for r in failures() if r["at"] != "api>worker"]
        book = [r for r in runbook() if r["failure"] != "job-twice"]
        probs, warns = check_failures(packet(failures=rows, runbook=book))
        self.assertEqual(probs, [])
        self.assertEqual(len(link_warnings(warns)), 1)    # a row on worker>fcm says nothing about api>worker
        rows.append(dict(failures()[3], at="worker"))
        probs, warns = check_failures(packet(failures=rows, runbook=runbook()))
        self.assertEqual((probs, link_warnings(warns)), ([], []))   # a row on an end system covers the link

    def test_at_must_be_on_the_map(self):
        for at in ("nope", "app>nope", "app>api>worker", "", None, "api>app", "app>worker", "app>app"):
            p = packet()
            p["sections"][1]["failures"][0]["at"] = at
            self.assertTrue(any("`at`" in x for x in fail_problems(p)), at)

    def test_state_enum_and_no_default(self):
        for st, msg in ((None, "no `state`"), ("", "no `state`"), ("fixed", '"fixed" is not one of')):
            p = packet()
            p["sections"][1]["failures"][3]["state"] = st
            self.assertTrue(any(msg in x for x in fail_problems(p)), st)

    def test_required_fields(self):
        p = packet()
        del p["sections"][1]["failures"][0]["mode"]
        self.assertTrue(any("`mode` is required" in x for x in fail_problems(p)))
        for key in ("impact", "action"):
            p = packet()
            del p["sections"][1]["runbook"][0][key]
            self.assertTrue(any(f"runbook row 1: `{key}` is required" in x for x in fail_problems(p)), key)

    def test_hostile_refs_fail(self):
        for url in HOSTILE:
            p = packet()
            p["sections"][1]["failures"][0]["ref"] = url
            self.assertTrue(any("not a plain https://" in x for x in fail_problems(p)), repr(url))
            self.assertIsNone(safe_ref(url), repr(url))

    def test_github_ref_must_be_pinned(self):
        p = packet()
        p["sections"][1]["failures"][0]["ref"] = "https://github.com/example/notes-app/blob/main/sync/client.ts#L12"
        self.assertTrue(any("not pinned to a commit" in x for x in fail_problems(p)))
        p["sections"][1]["failures"][0]["ref"] = f"https://github.com/example/notes-app/blob/{SHA}/sync/client.ts"
        probs, warns = check_failures(p)
        self.assertEqual(probs, [])
        self.assertTrue(any("no lines" in w for w in warns))

    def test_doc_url_ref_passes(self):
        p = packet()
        p["sections"][1]["failures"][0]["ref"] = "https://firebase.google.com/docs/cloud-messaging/manage-tokens"
        self.assertEqual(fail_problems(p), [])

    def test_handled_needs_ref_or_source(self):
        p = packet()
        del p["sections"][1]["failures"][0]["ref"]
        self.assertTrue(any("`handled` needs `ref`" in x for x in fail_problems(p)))
        p["sections"][1]["failures"][0].update(source={"en": "The client retries with backoff."}, planned=True)
        self.assertEqual(fail_problems(p), [])

    def test_detected_needs_detect(self):
        p = packet()
        del p["sections"][1]["runbook"][4]["detect"]
        self.assertTrue(any("`detected` needs `detect` in its runbook row" in x for x in fail_problems(p)))

    def test_introduced_unhandled_must_be_a_pin(self):
        p = packet()
        del p["sections"][1]["failures"][1]["finding"]
        self.assertTrue(any("that is a finding" in x for x in fail_problems(p)))
        p["sections"][1]["failures"][1]["finding"] = 7
        self.assertTrue(any("`finding` 7 is not a pin" in x for x in fail_problems(p)))

    def test_finding_must_sit_on_the_same_boundary(self):
        p = packet()
        p["sections"][1]["failures"][3].update(introduced=True, finding=1)   # api>worker row, pin at worker>fcm
        out = fail_problems(p)
        self.assertTrue(any('pinned at "worker>fcm", not at this row' in x for x in out), out)

    def test_malformed_shapes_do_not_crash(self):
        for bad in ("x", 3, {"a": 1}, [None, "x", 3]):
            p = packet(failures=bad)
            self.assertTrue(fail_problems(p), repr(bad))
        for key, val in (("state", {}), ("state", ["handled"]), ("finding", [1]), ("finding", {}),
                         ("state", "toString"), ("at", 3)):
            p = packet()
            p["sections"][1]["failures"][1][key] = val
            self.assertTrue(fail_problems(p), (key, val))
        for key, val in (("systems", [None, "x", {"id": "app"}]), ("findings", 3), ("systems", 3)):
            p = packet(**{key: val})
            check_failures(p)                  # reports, never raises
        self.assertEqual(check_failures({"sections": {"a": 1}}), ([], []))
        p = packet(systems=[{"id": "a>b"}, {"id": "c"}], failures=[])
        probs, _ = check_failures(p)           # findings set, no ok: the coverage loop runs
        self.assertTrue(any('contains ">"' in x for x in probs))
        p = packet()
        p["sections"][1]["runbook"][0]["impact"] = [1]
        self.assertTrue(any("`impact` is required" in x for x in fail_problems(p)))
        for bad in ("x", 3, {"a": 1}):
            self.assertTrue(fail_problems(packet(runbook=bad)), repr(bad))
        for val in (3, [3], [], {}, ["api-down", 3], None):
            p = packet()
            p["sections"][1]["runbook"][0]["failure"] = val
            self.assertTrue(fail_problems(p), repr(val))
        p = packet()
        p["sections"][1]["runbook"].append(None)
        self.assertTrue(any("runbook row 6: must be an object" in x for x in fail_problems(p)))

    def test_ids_compare_as_the_page_prints_them(self):
        p = packet(systems=[{"id": True}, {"id": 1.0}], findings=[], ok={"en": "checked"},
                   failures=[dict(failures()[3], at="true>1")], runbook=[runbook()[3]])
        p["sections"] = p["sections"][1:]
        self.assertEqual(fail_problems(p), [])
        p = packet()
        p["sections"][1]["findings"][0]["n"] = [1]
        self.assertTrue(fail_problems(p))      # finding 1 no longer names a pin, and nothing crashed

    def test_github_ref_shapes(self):
        for ref, msg in ((f"https://github.com/o/r/blob/{SHA.upper()}/a.go#L1C2-L3C4", None),
                         ("https://github.com/o/r/blob/main/a.go#L1", "not pinned"),
                         ("https://www.github.com/o/r/blame/main/a.go#L1", "not pinned"),
                         ("https://github.com/o/r/tree/main/a", "not a GitHub file permalink"),
                         ("https://raw.githubusercontent.com/o/r/main/a.go", "raw GitHub link not pinned"),
                         ("https://github.com/o/r/edit/main/a.go", "not a GitHub file permalink"),
                         (f"https://raw.githubusercontent.com/o/r/{SHA}/a.go", None),
                         ("https://raw.github.com/evil/realrepo/main/a.go", "raw GitHub link not pinned"),
                         (f"https://raw.github.com/o/r/{SHA}/a.go", None),
                         ("https://media.githubusercontent.com/media/o/r/main/big.bin", "raw GitHub link not pinned"),
                         (f"https://github.com/evil/r?x=/blob/{SHA}/a.go", None),   # opens the repo root; owner shown is real
                         (f"https://github.com/o/r/blob/{SHA}/a.go#Lx", "not a GitHub file permalink")):
            p = packet()
            p["sections"][1]["failures"][0]["ref"] = ref
            out = " ".join(fail_problems(p))
            if msg:
                self.assertIn(msg, out, ref)
            else:
                self.assertEqual(out, "", ref)

    def test_register_scan_skips_ids_but_reads_prose(self):
        p = packet()
        p["sections"][1]["failures"][0]["at"] = "app>api"
        p["sections"][1]["runbook"][0]["impact"] = {"en": "the retry_queue fills"}
        p["sections"][1]["runbook"][1]["failure"] = "fcm_unregistered_ids_are_ids"
        found = " ".join(verify.check_register(p))
        self.assertIn("retry_queue", found)
        self.assertNotIn('"app>api"', found)
        self.assertNotIn("fcm_unregistered", found)        # a cited id is a key, not prose


class VerifyRunbook(unittest.TestCase):
    """One home per fact: the map row names the mode, its runbook row says the rest."""

    def test_ids_are_anchors_and_unique(self):
        for bad in ("", " x", "a b", "-x", "x" * 65, "é", 3, '"><b>'):
            p = packet()
            p["sections"][1]["failures"][0]["id"] = bad
            self.assertTrue(any("`id`" in x for x in fail_problems(p)), repr(bad))
        p = packet()
        p["sections"][1]["failures"][2]["id"] = "fcm-unregistered"
        self.assertTrue(any("ids are unique" in x for x in fail_problems(p)))

    def test_every_mode_has_exactly_one_runbook_row(self):
        p = packet()
        del p["sections"][1]["runbook"][3]
        self.assertTrue(any("`job-twice`" in x and "no runbook row" in x for x in fail_problems(p)))
        p = packet()
        p["sections"][1]["runbook"].append(dict(runbook()[3]))
        self.assertTrue(any("2 runbook rows cite it" in x for x in fail_problems(p)))

    def test_cited_ids_resolve(self):
        for bad in ("no-such-mode", "#1", "API-DOWN"):
            p = packet()
            p["sections"][1]["runbook"].append({"failure": bad, "impact": {"en": "x"}, "action": {"en": "y"}})
            self.assertTrue(any(f'cites failure "{bad}"' in x for x in fail_problems(p)), bad)

    def test_one_row_may_handle_several_modes(self):
        p = packet()
        book = p["sections"][1]["runbook"]
        book[1]["failure"] = ["fcm-unregistered", "fcm-5xx"]
        del book[2]
        self.assertEqual(fail_problems(p), [])
        book[0]["failure"] = ["api-down", "api-down"]
        self.assertTrue(any("same failure id twice" in x for x in fail_problems(p)))

    def test_symptom_rows(self):
        p = packet()
        p["sections"][1]["runbook"].append({"symptom": {"en": "users report `E_SYNC_409` on save"},
                                            "detect": {"en": "support tag `sync-409`"},
                                            "impact": {"en": "the save fails"}, "action": {"en": "reload"}})
        self.assertEqual(fail_problems(p), [])
        del p["sections"][1]["runbook"][-1]["symptom"]
        self.assertTrue(any("cites no failure id and has no `symptom`" in x for x in fail_problems(p)))

    def test_one_home_per_fact(self):
        p = packet()
        p["sections"][1]["failures"][0]["action"] = {"en": "retry"}
        out = fail_problems(p)
        self.assertTrue(any("`action` written here and in the runbook row" in x for x in out), out)

    def test_no_signal_today_is_allowed_and_flagged(self):
        p = packet()
        for r in p["sections"][1]["runbook"]:
            r.pop("detect", None)
        p["sections"][1]["failures"][4]["state"] = "unhandled"     # detected would need a signal
        probs, warns = check_failures(p)
        self.assertEqual(probs, [])
        self.assertIn("no signal today for 5 runbook row(s)", quiet(warns)[0])

    def test_legacy_packet_warns_to_migrate_never_fails(self):
        probs, warns = check_failures(packet(failures=legacy_failures(), runbook=None))
        self.assertEqual(probs, [])
        self.assertTrue(any("have no `id`" in w and "migrate" in w for w in warns), warns)
        self.assertTrue(any("carry detect / impact / action on the map" in w for w in warns), warns)
        self.assertEqual(len(quiet(warns)), 1)                     # the moved rows are checked like any other
        self.assertIn(": #2 ", quiet(warns)[0])                    # numbered as the page draws it (RenderedLegacyPacket)
        self.assertTrue(any("4 = #2" in w for w in warns), warns)  # packet position and page number side by side

    def test_system_without_id_is_named_as_the_page_names_it(self):
        p = packet(failures=legacy_failures(), runbook=None, hops={})
        del p["sections"][1]["systems"][0]["id"]
        p["sections"][1]["failures"][0]["at"] = "null>api"        # the page would print "undefined"
        self.assertTrue(any('`at` "null>api"' in x for x in fail_problems(p)))

    def test_legacy_rules_still_hold(self):
        rows = legacy_failures()
        del rows[4]["detect"]
        self.assertTrue(any("`detected` needs `detect`" in x
                            for x in fail_problems(packet(failures=rows, runbook=None))))
        rows = legacy_failures()
        del rows[0]["impact"]
        self.assertTrue(any("`impact` is required" in x
                            for x in fail_problems(packet(failures=rows, runbook=None))))
        rows = legacy_failures()
        for k in ("detect", "impact", "action"):
            rows[3].pop(k, None)
        self.assertTrue(any("no runbook row" in x for x in fail_problems(packet(failures=rows, runbook=None))))

    def test_half_migrated_packet(self):
        rows = legacy_failures()
        rows[0]["id"] = "api-down"
        rows[0] = {k: v for k, v in rows[0].items() if k not in ("detect", "impact", "action")}
        probs, warns = check_failures(packet(failures=rows, runbook=[runbook()[0]]))
        self.assertEqual(probs, [])
        self.assertTrue(any("carry detect / impact / action" in w for w in warns))

    def test_runbook_links_follow_the_link_rule(self):
        p = packet()
        p["sections"][1]["runbook"][0]["action"] = {"en": "see [runbook](javascript:alert(1))"}
        self.assertTrue(verify.check_links(p))
        p["sections"][1]["runbook"][0]["action"] = {"en": "see [runbook](https://docs.example.com/push)"}
        self.assertEqual(verify.check_links(p), [])


class VerifyCommandLine(unittest.TestCase):
    """A packet written before `failures` existed: one clear line, never a traceback."""

    def run_verify(self, spec, register):
        tmp = Path(tempfile.mkdtemp(prefix="baton-fm-"))
        spec = copy.deepcopy(spec)
        spec["context"] = "Say you do not know when the record does not show it. " * 40 + "\n## Boundary review\n"
        (tmp / "p.json").write_text(json.dumps(spec))
        subprocess.run([sys.executable, str(ROOT / "scripts" / "render.py"), str(tmp / "p.json"),
                        "-o", str(tmp / "p.html")], check=True, capture_output=True)
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "verify.py"), str(tmp / "p.html"),
                               "--register", register], capture_output=True, text=True)

    def test_packet_from_before_the_runbook_passes_with_migration_warnings(self):
        r = self.run_verify(packet(failures=legacy_failures(), runbook=None), "engineer")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("migrate", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_legacy_packet(self):
        r = self.run_verify(packet(failures=None), "engineer")
        self.assertEqual(r.returncode, 1)
        self.assertIn("failure modes:", r.stderr)
        self.assertIn("no `failures`", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_full_packet_passes_and_prints_warnings_without_failing(self):
        r = self.run_verify(packet(), "engineer")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_verify(packet(failures=[], runbook=[]), "engineer")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("warning(s)", r.stderr)


def page_fns(calls):
    src = (ROOT / "templates" / "packet.html").read_text()
    parts = [re.search(r"  const E = .*?\n(?=\n)", src, re.S).group(0),
             re.search(r"  function safeHref\(u\)\{.*?\n  \}\n", src, re.S).group(0),
             "".join(re.findall(r"  const (?:REF_HOST|DOT_SEG|EMPTY_SEG|GITHUB_HOST|GITHUB_ESC|REF_MAX)=.*?\n", src)),
             re.search(r"  function safeRef\(u\)\{.*?\n  \}\n", src, re.S).group(0),
             re.search(r"  function refLabel\(u\)\{.*?\n  \}\n", src, re.S).group(0)]
    js = "\n".join(parts).replace("const ", "var ") + "\nconsole.log(JSON.stringify(" + calls + "));"
    return json.loads(subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout)


@unittest.skipUnless(NODE, "node not installed")
class PageRefRule(unittest.TestCase):
    def test_hostile_refs_are_refused(self):
        out = page_fns(json.dumps(HOSTILE) + ".map(safeRef)")
        self.assertEqual(out, [None] * len(HOSTILE))

    def test_page_and_verify_agree(self):
        good = [REF, "https://firebase.google.com/docs/x", "HTTPS://EXAMPLE.COM/a"]
        out = page_fns(json.dumps(good + HOSTILE) + ".map(safeRef)")
        self.assertEqual(out, [safe_ref(u) for u in good + HOSTILE])

    def test_long_refs_are_linear(self):
        import time
        refs = ["https://" + "a" * 50000, "https://" + "a" * 2030, "https://github.com/" + "a/" * 1000 + "x"]
        t = time.monotonic()
        out = page_fns(json.dumps(refs) + ".map(safeRef)")
        self.assertLess(time.monotonic() - t, 2.0)              # node start-up included
        t = time.monotonic()
        mine = [safe_ref(u) for u in refs]
        self.assertLess(time.monotonic() - t, 0.5)
        self.assertEqual(out, mine)
        self.assertIsNone(mine[0])                              # over 2048 characters

    def test_labels(self):
        out = page_fns(json.dumps([REF, f"https://github.com/o/r/blob/{SHA}/a/b.py#L7C2-L9C1",
                                    f"https://www.github.com/o/r/blame/{SHA}/c.md?plain=1#L5",
                                    "https://github.com/o/r/pull/12345/files",
                                    "https://raw.github.com/realorg/realrepo/main/services/notifications/push/worker.go",
                                    "https://api.github.com/repos/evilorg/realrepo/contents/services/push/worker.go",
                                    f"https://github.com/evil/r?x=/blob/{SHA}/a.go",
                                    "https://firebase.google.com/docs/cloud-messaging/manage-tokens"]) +
                       ".map(refLabel)")
        out = [x.replace("\u2060", "") for x in out]
        self.assertEqual(out[:2], ["example/notes-api · worker.go:40–58", "o/r · b.py:7–9"])
        self.assertEqual(out[2], "o/r · c.md:5")
        self.assertEqual(out[3], "o/r · pull/12345/files")    # any GitHub link leads with owner/repo
        self.assertTrue(out[4].startswith("realorg/realrepo · "), out[4])
        self.assertTrue(out[5].startswith("api.github.com/repos/evilorg/…/"), out[5])    # head kept
        self.assertTrue(out[6].startswith("evil/r"), out[6])
        self.assertEqual(out[7], "firebase.google.com/docs/cloud-messaging/manage-tokens")


PROBE = """<script>
window.addEventListener('load',()=>setTimeout(()=>{
  document.querySelectorAll('article.step').forEach(a=>a.classList.add('on'));
  const q=s=>[...document.querySelectorAll(s)];
  const MAP='table.fmt:not(.rbt)', RB='table.rbt';
  const txt=s=>{ const e=document.querySelector(s); return e?e.textContent:''; };
  const out={cls:document.documentElement.className,
    groups:q('.fgroup').map(g=>g.dataset.fg),
    rows:q(MAP+' tbody tr:not(.fgh)').length, rbRows:q(RB+' tbody tr').length,
    mapIds:q(MAP+' td.fid').map(td=>td.textContent.replace(/[\\u2193\\s]/g,'')),
    mapText:txt(MAP), rbText:txt(RB),
    refs:q('a.fref').map(a=>({href:a.getAttribute('href'),target:a.getAttribute('target'),rel:a.getAttribute('rel'),text:a.textContent})),
    refused:q('.noref').map(e=>e.textContent),
    nosig:q(RB+' .nosig').length, quietIds:q(RB+' tr').filter(r=>r.querySelector('.nosig')).map(r=>{ const c=r.querySelector('a.fback code'); return c?c.textContent:''; }), mapNosig:q(MAP+' .nosig').length, planned:q('.fplan').length,
    pins:q(MAP+' .badge').map(b=>b.textContent),
    states:q(MAP+' .ktag').map(e=>e.className), rbStates:q(RB+' tr[data-st]').map(r=>r.dataset.st),
    onattrs:q('*').flatMap(e=>[...e.attributes].filter(x=>/^on/i.test(x.name)).map(x=>e.tagName+' '+x.name)),
    mapTargets:q('.bmap .fm').map(e=>e.dataset.at), imgs:q('main img, main script').length,
    fcmOrder:q('tbody.fgroup[data-fg="worker>fcm"] tr[data-st]').map(r=>r.dataset.st),
    roles:{table:q(MAP+'[role=table]').length, rowgroup:q(MAP+' [role=rowgroup]').length,
      rows:q(MAP+' tbody tr[role=row]').length, cells:q(MAP+' td[role=cell]').length,
      colheads:q(MAP+' th[role=columnheader]').length, rowheads:q(MAP+' th[role=rowheader]').length,
      rbCells:q(RB+' td[role=cell]').length, rbColheads:q(RB+' th[role=columnheader]').length}};
  // Both directions: every map ID opens a runbook row that links back to it.
  out.pairs=q(MAP+' a.fjump').map(a=>{ const row=a.closest('tr'); const t=document.getElementById(a.dataset.jump);
    return {id:a.textContent.replace(/[\\u2193\\s]/g,''), href:a.getAttribute('href')==='#'+a.dataset.jump,
      inRunbook:!!(t&&t.closest(RB)), back:!!(t&&[...t.querySelectorAll('a.fback')].some(b=>b.dataset.jump===row.id))}; });
  out.backs=q(RB+' a.fback').map(a=>{ const t=document.getElementById(a.dataset.jump); return !!(t&&t.closest(MAP)); });
  // Links a keyboard reaches and a screen reader names (its name holds the visible id).
  out.a11y=q('a.fjump,a.fback').map(a=>({tab:a.tabIndex, href:(a.getAttribute('href')||'').startsWith('#'),
    named:(a.getAttribute('aria-label')||'').includes(a.querySelector('code').textContent.replace(/\\u200b/g,'')),
    hidden:[...a.querySelectorAll('[aria-hidden=true]')].every(x=>/^[\\u2191\\u2193\\s\\u00a0]+$/.test(x.textContent))}));
  out.targetsFocusable=q(MAP+' tbody tr:not(.fgh),'+RB+' tbody tr').every(r=>r.getAttribute('tabindex')==='-1');
  const go=q(MAP+' a.fjump').find(a=>a.textContent.startsWith('fcm-unregistered'));
  if(go){ go.focus(); go.click(); const act=document.activeElement;
    out.jumped={active:act&&act.id, inRunbook:!!(act&&act.closest&&act.closest(RB)), flash:!!(act&&act.classList.contains('flash')),
      text:act?act.textContent:''};
    const back=act&&act.querySelector&&act.querySelector('a.fback');
    if(back){ back.click(); const a2=document.activeElement;
      out.returned={active:a2&&a2.id, inMap:!!(a2&&a2.closest&&a2.closest(MAP)), from:go.closest('tr').id,
        marked:q('.fgroup.on').map(g=>g.dataset.fg), pressed:q('.bmap .fm[aria-pressed=true]').map(e=>e.dataset.at),
        rbMarked:q(RB+' tr.on').length}; } }
  const k0=q('.bmap .fm.on')[0]; if(k0) k0.click();   // clear before the map checks
  const t=document.querySelector('.bmap .carrow.fm[data-at="worker>fcm"]'); if(t) t.click();
  out.marked=q('.fgroup.on').map(g=>g.dataset.fg);
  out.rbMarked=q(RB+' tr.on').map(r=>JSON.parse(r.dataset.ats));
  const k=document.querySelector('.bmap .cnode.fm[data-at="fcm"]');
  if(k) k.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
  out.markedKey=q('.fgroup.on').map(g=>g.dataset.fg);
  out.pressed=q('.bmap .fm[aria-pressed=true]').map(e=>e.dataset.at);
  out.controls=q('.bmap .fm').every(e=>document.getElementById(e.getAttribute('aria-controls')));
  if(k) k.click(); out.cleared=q('.fgroup.on').length+q(RB+' tr.on').length;
  const pre=document.createElement('pre'); pre.id='fm-out'; pre.textContent=JSON.stringify(out);
  document.body.appendChild(pre);},400));
</script></body>"""


def probe(spec):
    spec = copy.deepcopy(spec)
    spec["context"] = "Say you do not know. " * 100 + "\n## Boundary review\n"
    tmp = Path(tempfile.mkdtemp(prefix="baton-fm-"))
    (tmp / "p.json").write_text(json.dumps(spec))
    subprocess.run([sys.executable, str(ROOT / "scripts" / "render.py"), str(tmp / "p.json"),
                    "-o", str(tmp / "p.html")], check=True, capture_output=True)
    head, _, tail = (tmp / "p.html").read_text().rpartition("</body>")
    (tmp / "probe.html").write_text(head + PROBE + tail)
    dom = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--virtual-time-budget=4000",
                          "--dump-dom", (tmp / "probe.html").as_uri()],
                         capture_output=True, text=True, timeout=120).stdout
    m = re.search(r'<pre id="fm-out">(.*?)</pre>', dom, re.S)
    return json.loads(htmlmod.unescape(m.group(1))) if m else None


@unittest.skipUnless(CHROME, "no Chrome")
class RenderedFailures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = packet()
        rows = spec["sections"][1]["failures"]
        rows[1], rows[2] = rows[2], rows[1]          # handled first in the packet
        # Rows below are written the old way (no id, runbook fields on the row):
        # the page numbers them and moves their fields into the runbook.
        rows.append({"at": "api", "mode": {"en": "a planned cache goes stale"},
                     "impact": {"en": "old notes show"}, "action": {"en": "expire after 60 s"},
                     "state": "unhandled", "planned": True,
                     "source": {"en": "The cache is refreshed every minute."}})
        rows.append({"at": "fcm", "mode": {"en": '"><img src=x onerror="' + on("mode") + '">'},
                     "detect": {"en": "<script>" + on("detect") + "</script>"},
                     "impact": {"en": "[x](javascript:" + on("impact") + ")"}, "action": {"en": "y"},
                     "state": "toString", "finding": '"><b>', "id": '"><i onclick=' + on("id") + '>'})
        rows.append(["not", "a", "row"])
        for i, url in enumerate(HOSTILE):
            rows.append({"at": "app", "mode": {"en": f"hostile {i}"}, "impact": {"en": "x"},
                         "action": {"en": "y"}, "ref": url, "state": "unhandled"})
        spec["sections"][1]["runbook"].append({"failure": ['"><b>', "nope"], "symptom": {"en": "<b>" + on("sym") + "</b>"},
                                               "impact": {"en": "x"}, "action": {"en": "y"}})
        cls.out = probe(spec)
        cls.n_hostile = len(HOSTILE)

    def setUp(self):
        self.assertIsNotNone(self.out, "the probe never ran — the page broke")

    def test_grouped_in_map_order(self):
        self.assertEqual(self.out["groups"], ["app", "app>api", "api", "api>worker", "worker>fcm", "fcm"])
        self.assertEqual(self.out["rows"], 7 + self.n_hostile)   # the array row is skipped
        self.assertEqual(self.out["rbRows"], 7 + self.n_hostile + 1)   # + the symptom row citing nothing real

    def test_map_carries_no_runbook_prose(self):
        mp, rb = self.out["mapText"], self.out["rbText"]
        for fact in ("api_5xx_ratio", "never gets reminders", "dedupe on job id", "rotate the key"):
            self.assertNotIn(fact, mp, fact)
            self.assertIn(fact, rb, fact)
        for col in ("Signal before", "What the user sees", "What to do"):
            self.assertNotIn(col, mp)

    def test_ids_on_the_map(self):
        ids = self.out["mapIds"]
        for fid in IDS:
            self.assertIn(fid, ids)
        legacy = [i for i in ids if i.startswith("#")]
        self.assertEqual(len(legacy), 2 + self.n_hostile)        # numbered where the table draws them
        self.assertEqual(legacy[:2], ["#1", "#2"])                # the hostile app rows come first

    def test_anchors_resolve_both_ways(self):
        pairs = self.out["pairs"]
        self.assertEqual(len(pairs), self.out["rows"])            # every mode on the map opens a runbook row
        for x in pairs:
            self.assertEqual((x["href"], x["inRunbook"], x["back"]), (True, True, True), x)
        self.assertTrue(self.out["backs"] and all(self.out["backs"]))

    def test_links_are_keyboard_and_screen_reader_reachable(self):
        self.assertTrue(self.out["a11y"])
        for x in self.out["a11y"]:
            self.assertEqual((x["tab"], x["href"], x["named"], x["hidden"]), (0, True, True, True), x)
        self.assertTrue(self.out["targetsFocusable"])

    def test_jump_moves_focus_and_never_sets_a_mark(self):
        j = self.out["jumped"]
        self.assertTrue(j["inRunbook"] and j["flash"], j)
        self.assertIn("never gets reminders", j["text"])
        r = self.out["returned"]
        self.assertEqual((r["active"], r["inMap"]), (r["from"], True), r)
        self.assertEqual((r["marked"], r["pressed"], r["rbMarked"]), ([], [], 0))   # focus only, no mark to undo

    def test_only_https_links_open_in_a_new_tab(self):
        refs = self.out["refs"]
        self.assertEqual(len(refs), 3)
        for r in refs:
            self.assertTrue(r["href"].startswith("https://"), r)
            self.assertEqual((r["target"], r["rel"]), ("_blank", "noopener noreferrer"))
        self.assertEqual(refs[1]["text"].replace("\u2060", ""), "example/notes-api · worker.go:40–58")

    def test_hostile_refs_render_as_text(self):
        self.assertEqual(self.out["refused"].count("link refused"), self.n_hostile)
        self.assertNotIn("pwned", self.out["cls"])
        self.assertEqual(self.out["onattrs"], [])

    def test_gaps_are_named(self):
        self.assertIn("no code reference", self.out["refused"])
        self.assertIn("not on the map", self.out["refused"])      # a runbook row citing an unknown id
        self.assertEqual(self.out["nosig"], 3 + self.n_hostile)   # job-twice, planned cache, symptom row, hostile rows
        self.assertEqual(self.out["mapNosig"], 0)                 # every mode has its runbook row
        self.assertEqual(self.out["planned"], 1)
        self.assertEqual(self.out["pins"], ["1", '"><b>'])
        self.assertIn("ktag ", self.out["states"])    # "toString" renders as state not given
        self.assertEqual(self.out["imgs"], 0)
        self.assertIn("ktag ok", self.out["states"])
        self.assertIn("ktag warn", self.out["states"])
        self.assertIn("ktag risk", self.out["states"])
        self.assertEqual(self.out["rbStates"], [])                # state lives on the map row only

    def test_worst_first_within_a_boundary(self):
        # the packet lists handled before unhandled here; the page must put unhandled first
        self.assertEqual(self.out["fcmOrder"], ["unhandled", "handled"])

    def test_cards_keep_table_semantics(self):
        r, n = self.out["roles"], len(self.out["groups"])
        self.assertEqual((r["table"], r["colheads"], r["rowheads"]), (1, 4, n))
        self.assertEqual(r["rowgroup"], n + 1)
        self.assertEqual(r["cells"], 4 * self.out["rows"])
        self.assertEqual(r["rows"], self.out["rows"] + n)
        self.assertEqual((r["rbColheads"], r["rbCells"]), (4, 4 * self.out["rbRows"]))

    def test_map_marks_rows(self):
        self.assertIn("worker>fcm", self.out["mapTargets"])
        self.assertEqual(self.out["marked"], ["worker>fcm"])
        self.assertTrue(self.out["rbMarked"] and all("worker>fcm" in a for a in self.out["rbMarked"]))
        self.assertEqual(self.out["markedKey"], ["fcm"])
        self.assertEqual(self.out["pressed"], ["fcm"])
        self.assertTrue(self.out["controls"])
        self.assertEqual(self.out["cleared"], 0)      # a second click clears the mark


@unittest.skipUnless(CHROME, "no Chrome")
class RenderedLegacyPacket(unittest.TestCase):
    """A packet written before ids and the runbook: same facts on the page,
    detect / impact / action moved into generated runbook rows."""

    @classmethod
    def setUpClass(cls):
        cls.out = probe(packet(failures=legacy_failures(), runbook=None))

    def test_migrates(self):
        o = self.out
        self.assertIsNotNone(o)
        self.assertEqual(o["mapIds"], ["#1", "#2", "#3", "#4", "#5"])      # numbered as drawn
        self.assertEqual(o["rbRows"], 5)
        self.assertNotIn("api_5xx_ratio", o["mapText"])
        self.assertIn("api_5xx_ratio", o["rbText"])
        self.assertEqual(o["nosig"], 1)
        self.assertEqual(o["quietIds"], ["#2"])                       # the same number verify prints
        self.assertTrue(all(x["inRunbook"] and x["back"] for x in o["pairs"]) and len(o["pairs"]) == 5)


LONG_REF = ("https://github.com/a-very-long-organisation-name/an-even-longer-repository-name-here/blob/"
            f"{SHA}/services/notifications/push/delivery/worker_retry_policy_handler.go#L1200-L1288")
LONG_METRIC = ("notifications_push_delivery_worker_retry_policy_handler_unregistered_token_errors_total"
               '{code="UNREGISTERED",region="eu-west-1"}')


@unittest.skipUnless(CHROME, "no Chrome")
class LongValuesOnPhones(unittest.TestCase):
    """A long permalink and a long metric name never scroll the page sideways:
    snapshot.py's layout pass (320 and 390 px among others, both themes) must
    report nothing."""

    def test_snapshot_passes_with_long_ref_and_metric(self):
        spec = packet()
        rows, book = spec["sections"][1]["failures"], spec["sections"][1]["runbook"]
        long_id = "push-delivery.worker_retry-policy-unregistered-token-errors-x" + "y" * 3
        rows.append(dict(rows[2], id=long_id, ref=LONG_REF))
        book.append(dict(book[2], failure=long_id, detect={"en": "`" + LONG_METRIC + "`"}))
        rows.append(dict(rows[0], id="api-down-2", ref="https://docs.example.com/" + "x" * 160))
        book.append(dict(book[0], failure="api-down-2", detect={"en": LONG_METRIC.split("{")[0]}))
        spec["context"] = "Say you do not know. " * 100 + "\n## Boundary review\n"
        tmp = Path(tempfile.mkdtemp(prefix="baton-fm-long-"))
        (tmp / "p.json").write_text(json.dumps(spec))
        subprocess.run([sys.executable, str(ROOT / "scripts" / "render.py"), str(tmp / "p.json"),
                        "-o", str(tmp / "p.html")], check=True, capture_output=True)
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "snapshot.py"), str(tmp / "p.html"),
                            "-o", str(tmp / "shots")], capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("sideways", r.stdout)
        # Above the card breakpoint both tables fit their card: State is never pushed
        # into the table's own sideways scroll, even with the long owner/repo.
        page = (tmp / "p.html").read_text()
        probe = ("<script>window.addEventListener('load',()=>{document.getElementById('next').click();"
                 "setTimeout(()=>{const t=[...document.querySelectorAll('.fmodes .tscroll')];const p=document.createElement('pre');"
                 "p.id='fit';p.textContent=t.length===2?Math.max(...t.map(x=>x.scrollWidth-x.clientWidth)):-999;"
                 "document.body.appendChild(p);},300)});</script></body>")
        head, _, tail = page.rpartition("</body>")
        (tmp / "fit.html").write_text(head + probe + tail)
        for w in (905, 1024, 1280):
            dom = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--virtual-time-budget=3000",
                                  f"--window-size={w},1500", "--dump-dom", (tmp / "fit.html").as_uri()],
                                 capture_output=True, text=True, timeout=120).stdout
            m = re.search(r'<pre id="fit">(-?\d+)</pre>', dom)
            self.assertIsNotNone(m, w)
            self.assertNotEqual(int(m.group(1)), -999, "the map table and the runbook both render")
            self.assertLessEqual(int(m.group(1)), 0, f"{w}px: a table scrolls inside its card")


if __name__ == "__main__":
    unittest.main()
