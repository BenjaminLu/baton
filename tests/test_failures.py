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
           "https://a/'x", "https://a/<b>", "java\u0000script:x", "\u007fhttps://evil.example"]


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


def failures():
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


def packet(**boundary):
    b = {"kind": "boundary", "role": "boundary-review", "heading": {"en": "Where it can break"},
         "systems": [{"id": "app", "name": {"en": "Notes app"}, "kind": "client"},
                     {"id": "api", "name": {"en": "API"}}, {"id": "worker", "name": {"en": "Push worker"}},
                     {"id": "fcm", "name": {"en": "FCM"}, "kind": "external"}],
         "hops": {"0": "HTTPS", "1": "job", "2": "HTTP v1"},
         "findings": [{"n": 1, "at": "worker>fcm", "lens": "dependency", "tone": "warn",
                       "title": {"en": "dead tokens are retried forever"}, "card": "Dead tokens are retried"}],
         "failures": failures()}
    b.update(boundary)
    b = {k: v for k, v in b.items() if v is not None}
    return {"title": {"en": "failure modes"}, "sections": [chain("Dead tokens are retried"), b]}


def fail_problems(data, register="engineer"):
    return check_failures(data, register)[0]


class VerifyFailures(unittest.TestCase):
    def test_clean_packet_passes(self):
        self.assertEqual(check_failures(packet()), ([], []))

    def test_missing_failures_fails_engineer_warns_eli5(self):
        p = packet(failures=None)
        probs, warns = check_failures(p, "engineer")
        self.assertEqual(len(probs), 1)
        self.assertIn("no `failures`", probs[0])
        probs, warns = check_failures(p, "eli5")
        self.assertEqual(probs, [])
        self.assertEqual(len(warns), 1)

    def test_empty_list_warns_per_uncovered_link(self):
        probs, warns = check_failures(packet(failures=[]))
        self.assertEqual(probs, [])
        self.assertEqual(sorted(re.search(r'link "([^"]+)"', w).group(1) for w in warns),
                         ["api>worker", "app>api", "worker>fcm"])

    def test_ok_line_silences_coverage_warning(self):
        p = packet(failures=[], findings=[], ok={"en": "UI-only change; nothing crosses a boundary"})
        p["sections"] = p["sections"][1:]
        self.assertEqual(check_failures(p), ([], []))

    def test_endpoint_row_covers_its_links(self):
        rows = [r for r in failures() if r["at"] != "api>worker"]
        _, warns = check_failures(packet(failures=rows))
        self.assertEqual(len(warns), 1)    # a row on worker>fcm says nothing about api>worker
        rows.append(dict(failures()[3], at="worker"))
        _, warns = check_failures(packet(failures=rows))
        self.assertEqual(warns, [])        # a row on an end system covers the link

    def test_at_must_be_on_the_map(self):
        for at in ("nope", "app>nope", "app>api>worker", "", None):
            p = packet()
            p["sections"][1]["failures"][0]["at"] = at
            self.assertTrue(any("`at`" in x for x in fail_problems(p)), at)

    def test_state_enum_and_no_default(self):
        for st, msg in ((None, "no `state`"), ("", "no `state`"), ("fixed", '"fixed" is not one of')):
            p = packet()
            p["sections"][1]["failures"][3]["state"] = st
            self.assertTrue(any(msg in x for x in fail_problems(p)), st)

    def test_required_fields(self):
        for key in ("mode", "impact", "action"):
            p = packet()
            del p["sections"][1]["failures"][0][key]
            self.assertTrue(any(f"`{key}` is required" in x for x in fail_problems(p)), key)

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
        del p["sections"][1]["failures"][4]["detect"]
        self.assertTrue(any("`detected` needs `detect`" in x for x in fail_problems(p)))

    def test_introduced_unhandled_must_be_a_pin(self):
        p = packet()
        del p["sections"][1]["failures"][1]["finding"]
        self.assertTrue(any("that is a finding" in x for x in fail_problems(p)))
        p["sections"][1]["failures"][1]["finding"] = 7
        self.assertTrue(any("`finding` 7 is not a pin" in x for x in fail_problems(p)))

    def test_malformed_shapes_do_not_crash(self):
        for bad in ("x", 3, {"a": 1}, [None, "x", 3]):
            p = packet(failures=bad)
            self.assertTrue(fail_problems(p), repr(bad))
        for key, val in (("state", {}), ("state", ["handled"]), ("finding", [1]), ("finding", {}),
                         ("state", "toString"), ("at", 3)):
            p = packet()
            p["sections"][1]["failures"][1][key] = val
            self.assertTrue(fail_problems(p), (key, val))
        p = packet()
        p["sections"][1]["findings"][0]["n"] = [1]
        self.assertTrue(fail_problems(p))      # finding 1 no longer names a pin, and nothing crashed

    def test_github_ref_shapes(self):
        for ref, msg in ((f"https://github.com/o/r/blob/{SHA.upper()}/a.go#L1C2-L3C4", None),
                         ("https://github.com/o/r/blob/main/a.go#L1", "not pinned"),
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
        p["sections"][1]["failures"][0]["impact"] = {"en": "the retry_queue fills"}
        found = " ".join(verify.check_register(p))
        self.assertIn("retry_queue", found)
        self.assertNotIn('"app>api"', found)


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

    def test_legacy_packet(self):
        r = self.run_verify(packet(failures=None), "engineer")
        self.assertEqual(r.returncode, 1)
        self.assertIn("failure modes:", r.stderr)
        self.assertIn("no `failures`", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_full_packet_passes_and_prints_warnings_without_failing(self):
        r = self.run_verify(packet(), "engineer")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_verify(packet(failures=[]), "engineer")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("warning(s)", r.stderr)


def page_fns(calls):
    src = (ROOT / "templates" / "packet.html").read_text()
    parts = [re.search(r"  const E = .*?\n(?=\n)", src, re.S).group(0),
             re.search(r"  function safeHref\(u\)\{.*?\n  \}\n", src, re.S).group(0),
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

    def test_labels(self):
        out = page_fns(json.dumps([REF, f"https://github.com/o/r/blob/{SHA}/a/b.py#L7",
                                    "https://firebase.google.com/docs/cloud-messaging/manage-tokens"]) +
                       ".map(refLabel)")
        self.assertEqual(out[:2], ["worker.go:40–58", "b.py:7"])
        self.assertTrue(out[2].startswith("firebase.google.com/…"), out[2])


PROBE = """<script>
window.addEventListener('load',()=>setTimeout(()=>{
  document.querySelectorAll('article.step').forEach(a=>a.classList.add('on'));
  const q=s=>[...document.querySelectorAll(s)];
  const out={cls:document.documentElement.className,
    groups:q('.fgroup').map(g=>g.dataset.fg),
    rows:q('table.fmt tbody tr:not(.fgh)').length,
    refs:q('a.fref').map(a=>({href:a.getAttribute('href'),target:a.getAttribute('target'),rel:a.getAttribute('rel'),text:a.textContent})),
    refused:q('.noref').map(e=>e.textContent),
    nosig:q('.nosig').length, planned:q('.fplan').length, pins:q('table.fmt .badge').map(b=>b.textContent),
    states:q('table.fmt .ktag').map(e=>e.className),
    onattrs:q('*').flatMap(e=>[...e.attributes].filter(x=>/^on/i.test(x.name)).map(x=>e.tagName+' '+x.name)),
    mapTargets:q('.bmap .fm').map(e=>e.dataset.at), imgs:q('main img, main script').length};
  const t=document.querySelector('.bmap .carrow.fm[data-at="worker>fcm"]'); if(t) t.click();
  out.marked=q('.fgroup.on').map(g=>g.dataset.fg);
  const k=document.querySelector('.bmap .cnode.fm[data-at="fcm"]');
  if(k) k.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
  out.markedKey=q('.fgroup.on').map(g=>g.dataset.fg);
  out.pressed=q('.bmap .fm[aria-pressed=true]').map(e=>e.dataset.at);
  out.controls=q('.bmap .fm').every(e=>document.getElementById(e.getAttribute('aria-controls')));
  if(k) k.click(); out.cleared=q('.fgroup.on').length;
  const pre=document.createElement('pre'); pre.id='fm-out'; pre.textContent=JSON.stringify(out);
  document.body.appendChild(pre);},400));
</script></body>"""


@unittest.skipUnless(CHROME, "no Chrome")
class RenderedFailures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = packet()
        rows = spec["sections"][1]["failures"]
        rows.append({"at": "api", "mode": {"en": "a planned cache goes stale"},
                     "impact": {"en": "old notes show"}, "action": {"en": "expire after 60 s"},
                     "state": "unhandled", "planned": True,
                     "source": {"en": "The cache is refreshed every minute."}})
        rows.append({"at": "fcm", "mode": {"en": '"><img src=x onerror="' + on("mode") + '">'},
                     "detect": {"en": "<script>" + on("detect") + "</script>"},
                     "impact": {"en": "[x](javascript:" + on("impact") + ")"}, "action": {"en": "y"},
                     "state": "toString", "finding": '"><b>'})
        rows.append(["not", "a", "row"])
        for i, url in enumerate(HOSTILE):
            rows.append({"at": "app", "mode": {"en": f"hostile {i}"}, "impact": {"en": "x"},
                         "action": {"en": "y"}, "ref": url, "state": "unhandled"})
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
        cls.out = json.loads(htmlmod.unescape(m.group(1))) if m else None
        cls.n_hostile = len(HOSTILE)

    def setUp(self):
        self.assertIsNotNone(self.out, "the probe never ran — the page broke")

    def test_grouped_in_map_order(self):
        self.assertEqual(self.out["groups"], ["app", "app>api", "api", "api>worker", "worker>fcm", "fcm"])
        self.assertEqual(self.out["rows"], 7 + self.n_hostile)   # the array row is skipped

    def test_only_https_links_open_in_a_new_tab(self):
        refs = self.out["refs"]
        self.assertEqual(len(refs), 3)
        for r in refs:
            self.assertTrue(r["href"].startswith("https://"), r)
            self.assertEqual((r["target"], r["rel"]), ("_blank", "noopener noreferrer"))
        self.assertEqual(refs[1]["text"].replace("​", ""), "worker.go:40–58 ↗".replace(" ↗", ""))

    def test_hostile_refs_render_as_text(self):
        self.assertEqual(self.out["refused"].count("link refused"), self.n_hostile)
        self.assertNotIn("pwned", self.out["cls"])
        self.assertEqual(self.out["onattrs"], [])

    def test_gaps_are_named(self):
        self.assertIn("no code reference", self.out["refused"])
        self.assertEqual(self.out["nosig"], 2 + self.n_hostile)   # api>worker, planned cache, hostile rows
        self.assertEqual(self.out["planned"], 1)
        self.assertEqual(self.out["pins"], ["1", '"><b>'])
        self.assertIn("ktag ", self.out["states"])    # "toString" renders as state not given
        self.assertEqual(self.out["imgs"], 0)
        self.assertIn("ktag ok", self.out["states"])
        self.assertIn("ktag warn", self.out["states"])
        self.assertIn("ktag risk", self.out["states"])

    def test_map_marks_rows(self):
        self.assertIn("worker>fcm", self.out["mapTargets"])
        self.assertEqual(self.out["marked"], ["worker>fcm"])
        self.assertEqual(self.out["markedKey"], ["fcm"])
        self.assertEqual(self.out["pressed"], ["fcm"])
        self.assertTrue(self.out["controls"])
        self.assertEqual(self.out["cleared"], 0)      # a second click clears the mark


if __name__ == "__main__":
    unittest.main()
