"""A row's number leads back to its place on the map, in a runbook and in the
boundary map's own failure table. Runs in headless Chrome (skipped when absent).
Run: python3 -m unittest discover -s tests"""
import copy, html as htmlmod, json, re, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from test_attacks import CHROME, on  # noqa: E402
from test_system_map import GOOD  # noqa: E402
import test_failures as TF  # noqa: E402

PROBE = """<script>
window.addEventListener('load',()=>setTimeout(()=>{
  document.querySelectorAll('article.step').forEach(a=>a.classList.add('on'));
  const q=(s,r)=>[...(r||document).querySelectorAll(s)];
  const out={onattrs:q('*').flatMap(e=>[...e.attributes].filter(x=>/^on/i.test(x.name)).map(x=>e.tagName+' '+x.name)),
             cls:document.documentElement.className, sections:[]};
  q('.kbox').forEach(kb=>{
    const links=q('table.fmt a.fno',kb), plain=q('table.fmt b.fno',kb);
    const sec={links:links.length, plain:plain.length,
      // each number names the place it leads to, and that place is the map box or link with its rows
      ok:links.map(a=>{ const t=document.getElementById(a.dataset.place); const row=a.closest('tbody.fgroup');
        return {href:a.getAttribute('href')==='#'+a.dataset.place, inMap:!!(t&&kb.contains(t)&&t.closest('.bmap')),
          same:!!(t&&row&&t.dataset.at===row.dataset.fg), tab:a.tabIndex,
          named:(a.getAttribute('aria-label')||'').includes(a.textContent)}; })};
    const a=links[links.length-1];
    if(a){ a.focus(); a.click(); const act=document.activeElement;
      sec.jump={focusedPlace:!!(act&&act.classList&&act.classList.contains('fm')&&act.id===a.dataset.place),
        flash:act.classList.contains('flash'), marked:q('.fgroup.on',kb).length, pressed:q('[aria-pressed=true]',kb).length};
      act.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
      sec.enterMarks=q('.fgroup.on',kb).map(g=>g.dataset.fg); }
    out.sections.push(sec);
  });
  const pre=document.createElement('pre'); pre.id='rl-out'; pre.textContent=JSON.stringify(out);
  document.body.appendChild(pre);},400));
</script></body>"""


def probe(spec):
    spec = copy.deepcopy(spec)
    spec["context"] = "Say you do not know. " * 100 + "\n## Boundary review\n"
    tmp = Path(tempfile.mkdtemp(prefix="baton-rl-"))
    (tmp / "p.json").write_text(json.dumps(spec))
    subprocess.run([sys.executable, str(ROOT / "scripts" / "render.py"), str(tmp / "p.json"), "-o", str(tmp / "p.html"),
                    "--force"], check=True, capture_output=True)
    head, _, tail = (tmp / "p.html").read_text().rpartition("</body>")
    (tmp / "probe.html").write_text(head + PROBE + tail)
    dom = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--virtual-time-budget=4000", "--dump-dom",
                          (tmp / "probe.html").as_uri()], capture_output=True, text=True, timeout=120).stdout
    m = re.search(r'<pre id="rl-out">(.*?)</pre>', dom, re.S)
    return json.loads(htmlmod.unescape(m.group(1))) if m else None


@unittest.skipUnless(CHROME, "no Chrome")
class RowNumberLeadsToTheMap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = copy.deepcopy(GOOD)
        rows = spec["sections"][2]["rows"]
        rows.append(dict(rows[0], at="br", mode={"en": "biz-relay down"}, state="unhandled"))
        rows.append(dict(rows[0], at="nowhere", mode={"en": "a row whose place is not drawn"}))
        # a hostile system id cannot break out of the place id or the link
        spec["systems"]["systems"].append({"id": '"><img src=x onerror="' + on("sys") + '">', "name": {"en": "x"}})
        rows.append(dict(rows[0], at=spec["systems"]["systems"][-1]["id"], mode={"en": "hostile place"}))
        cls.runbook = probe(spec)
        cls.boundary = probe(TF.packet())          # a boundary map that keeps its own failures

    def test_every_drawn_place_is_linked_both_ways(self):
        for out in (self.runbook, self.boundary):
            self.assertIsNotNone(out, "the probe never ran — the page broke")
            secs = [s for s in out["sections"] if s["links"]]
            self.assertTrue(secs)
            for s in secs:
                for x in s["ok"]:
                    self.assertEqual(x, {"href": True, "inMap": True, "same": True, "tab": 0, "named": True})

    def test_a_place_not_on_the_map_keeps_a_plain_number(self):
        rb = [s for s in self.runbook["sections"] if s["links"]][0]
        self.assertEqual(rb["plain"], 1)
        self.assertEqual(rb["links"], 3)

    def test_jump_focuses_the_place_without_a_mark_and_enter_marks(self):
        for out in (self.runbook, self.boundary):
            for s in (x for x in out["sections"] if x["links"]):
                j = s["jump"]
                self.assertEqual((j["focusedPlace"], j["flash"], j["marked"], j["pressed"]), (True, True, 0, 0), j)
                self.assertEqual(len(s["enterMarks"]), 1)

    def test_hostile_ids_stay_text(self):
        self.assertEqual(self.runbook["onattrs"], [])
        self.assertNotIn("pwned", self.runbook["cls"])


if __name__ == "__main__":
    unittest.main()
