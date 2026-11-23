"""Injection paths, end to end: render.py builds a hostile packet and real
headless Chrome loads it. Every payload, if it ran, would add a "pwned-*"
class to <html>; the page must show none, carry no event-handler attribute,
and link nowhere but http(s) or mailto. Skipped when no Chrome is found.

Run: python3 -m unittest discover -s tests
"""
import html as htmlmod, json, os, re, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import verify  # noqa: E402
from render import embed_json, embed_text  # noqa: E402


def _chrome():
    for c in (os.environ.get("BATON_CHROME"), os.environ.get("CHROME_BIN"),
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "/Applications/Chromium.app/Contents/MacOS/Chromium",
              shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chrome")):
        if c and Path(c).exists():
            return c


CHROME = _chrome()


def on(tag):
    return "document.documentElement.classList.add('pwned-%s')" % tag


SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 40" onload="{svg_onload}">'
       '<image href="x" onerror="{image}"/>'
       '<script>{script}</script>'
       '<foreignObject><img src="x" onerror="{fo}"/></foreignObject>'
       '<a href="javascript:{svg_a}"><text x="1" y="9">a</text></a>'
       '<animate attributeName="href" to="javascript:{anim}" begin="0s"/>'
       '<set attributeName="onmouseover" to="{set}"/>'
       '<use href="data:image/svg+xml,x"/>'
       '<rect width="10" height="10" style="fill:url(javascript:1)" onclick="{rect}"/>'
       '<text x="1" y="30" data-en="kept">kept</text>'
       '<defs><marker id="arr"><path d="M0 0L9 4z"/></marker></defs>'
       '<path id="edge" d="M0 0H9" marker-end="url(#arr)"/>'
       '<rect id="foot" width="1" height="1" style="background:\\75 rl(http://evil.test/a)"'
       ' fill="\\75 rl(http://evil.test/b)" stroke="u\\72 l(http://evil.test/c)"/>'
       '<rect id="next" width="1" height="1" style="mask:u\\rl(http://evil.test/d)"/>'
       '<rect id="prev" width="1" height="1"/>'
       '<rect width="1" height="1" style="background:image-set(\'http://evil.test/e\' 1x)"/>'
       '<rect width="1" height="1" style="background:-webkit-image-set(\'http://evil.test/f\' 1x)"/>'
       '<rect width="1" height="1" style="border-image-source:image-set(\'http://evil.test/g\' 1x)"/>'
       '<rect width="1" height="1" style="mask-image:image-set(\'http://evil.test/h\' 1x)"/>'
       '<rect width="1" height="1" style="background:element(#edge)"/>'
       '<rect width="1" height="1" style="background:paint(x)"/>'
       '<rect width="1" height="1" fill="cross-fade(red, blue)"/>'
       '<rect width="1" height="1" style="font-family:\'http://evil.test/i\'"/>'
       '<rect width="1" height="1" transform="translate(1,2) rotate(3)" fill="rgb(1,2,3)"'
       ' style="fill:var(--accent);width:calc(1px + 2px)"/>'
       '<style>@import "x";</style></svg>'
       '<img src="x" onerror="{img}">').format(
    svg_onload=on("svg-onload"), image=on("svg-image"), script=on("svg-script"), fo=on("svg-fo"),
    svg_a=on("svg-a"), anim=on("svg-animate"), set=on("svg-set"), rect=on("svg-rect"), img=on("svg-img"))

LINKS = ("[c1](\u0001javascript:x) [c2](\u001fjavascript:x) [c3](\u0001//evil.example) "
         "[c4](\u0001data:text/html,x) [c5](javascript:x) [c6](JaVaScRiPt:x) [c7](data:text/html,x) "
         "[c8](//evil.example) [c9](/\\evil.example) [c10](../relative.md) "
         "[c11](https://a\"onmouseover=\"" + on("quote") + ") "
         "[ok](https://ok.example/p?a=1&b=2) [mail](mailto:a@b.c)")

CONTEXT = ("Say you do not know when the record does not show it. " * 40 +
           "\n</SCRIPT><img src=x onerror=\"" + on("ctx-upper") + "\">"
           "\n<!--<script>" + on("ctx-comment") + "</script>-->"
           "\n## Boundary review\n")


def packet():
    return {
        "title": {"en": "attack {{CONTEXT}}"}, "filename": "attack",
        "format_version": "<img src=x onerror=\"" + on("fmt") + "\">",
        "layer": "<img src=x onerror=\"" + on("layer") + "\">",
        "layer_note": {"en": "<img src=x onerror=\"" + on("note") + "\">"},
        "sections": [
            {"kind": "figure", "heading": {"en": "fig"}, "svg": SVG},
            {"heading": {"en": "links"}, "text": [{"p": {"en": LINKS}}]},
            {"kind": "txn", "heading": {"en": "txn"}, "method": "m",
             "tables": [{"table": "t", "op": "UPDATE", "fields": [
                 {"k": "k", "now": "v", "tone": "x\" onmouseover=\"" + on("tone")}]}]},
        ],
        "context": CONTEXT,
    }


PROBE = """<script>
window.addEventListener('load',()=>setTimeout(()=>{
  const raw=document.getElementById('raw'); if(raw) raw.click();
  document.querySelectorAll('article.step').forEach(a=>a.classList.add('on'));
  document.querySelectorAll('*').forEach(e=>{
    e.dispatchEvent(new MouseEvent('mouseover',{bubbles:true}));
    e.dispatchEvent(new MouseEvent('click',{bubbles:false,cancelable:true}));});
  const out={cls:document.documentElement.className,
    hrefs:[...document.querySelectorAll('main a')].map(a=>a.getAttribute('href')),
    onattrs:[...document.querySelectorAll('*')].flatMap(e=>[...e.attributes]
      .filter(x=>/^on/i.test(x.name)).map(x=>e.tagName+' '+x.name)),
    svgTags:[...document.querySelectorAll('.figbody svg *')].map(e=>e.localName),
    cssFns:[...document.querySelectorAll('.figbody svg *')].flatMap(e=>[...e.attributes]
      .flatMap(x=>[...x.value.matchAll(/(-?[a-z_][\\w-]*)\\s*\\(/gi)].map(m=>m[1].toLowerCase()))),
    quotedUrl:[...document.querySelectorAll('.figbody svg *')].some(e=>[...e.attributes]
      .some(x=>/(["'])[^"']*(:|\\/\\/)[^"']*\\1/.test(x.value))),
    allowedKept:!!document.querySelector('.figbody svg rect[transform][style*="calc("]'),
    backslash:[...document.querySelectorAll('.figbody svg *')].flatMap(e=>[...e.attributes]
      .filter(x=>x.value.includes(String.fromCharCode(92))).map(x=>e.localName+' '+x.name)),
    byId:['foot','next','prev'].map(i=>(document.getElementById(i)||{}).tagName),
    footText:document.getElementById('foot').textContent.length,
    svgIds:[...document.querySelectorAll('.figbody svg [id]')].map(e=>e.id),
    marker:(document.querySelector('.figbody svg [marker-end]')||{getAttribute:()=>null}).getAttribute('marker-end'),
    kept:!!document.querySelector('.figbody svg text[data-en=kept]'),
    ctx:document.getElementById('baton-context').textContent.slice(-300),
    copied:(document.getElementById('rawtext')||{}).value, title:document.title,
    foot:document.getElementById('foot').textContent};
  const pre=document.createElement('pre'); pre.id='attack-out'; pre.textContent=JSON.stringify(out);
  document.body.appendChild(pre);},400));
</script></body>"""


@unittest.skipUnless(CHROME, "no Chrome")
class RenderedAttacks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = Path(tempfile.mkdtemp(prefix="baton-attack-"))
        (tmp / "p.json").write_text(json.dumps(packet()))
        subprocess.run([sys.executable, str(ROOT / "scripts" / "render.py"), str(tmp / "p.json"),
                        "-o", str(tmp / "p.html")], check=True, capture_output=True)
        page = (tmp / "p.html").read_text()
        head, _, tail = page.rpartition("</body>")
        (tmp / "probe.html").write_text(head + PROBE + tail)
        dom = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--virtual-time-budget=4000",
                              "--dump-dom", (tmp / "probe.html").as_uri()],
                             capture_output=True, text=True, timeout=120).stdout
        m = re.search(r'<pre id="attack-out">(.*?)</pre>', dom, re.S)
        cls.out = json.loads(htmlmod.unescape(m.group(1))) if m else None

    def setUp(self):
        self.assertIsNotNone(self.out, "the probe never ran — the page broke")

    def test_no_payload_ran(self):
        self.assertNotIn("pwned", self.out["cls"])

    def test_no_event_handler_attributes(self):
        self.assertEqual(self.out["onattrs"], [])

    def test_only_http_and_mailto_links(self):
        # the URL ends at the first ")", so the payload is cut there — and kept inside href
        self.assertEqual(self.out["hrefs"], ['https://a"onmouseover="' + on("quote")[:-1],
                                             "https://ok.example/p?a=1&b=2", "mailto:a@b.c"])

    def test_svg_keeps_drawing_drops_the_rest(self):
        self.assertTrue(self.out["kept"])
        self.assertTrue(set(self.out["svgTags"]) <= {"text", "rect", "defs", "marker", "path"},
                        self.out["svgTags"])

    def test_svg_css_escapes_are_dropped(self):
        self.assertEqual(self.out["backslash"], [])

    def test_svg_css_functions_are_allow_listed(self):
        self.assertTrue(set(self.out["cssFns"]) <= {"url", "var", "calc", "rgb", "translate", "rotate"},
                        self.out["cssFns"])
        self.assertFalse(self.out["quotedUrl"])
        self.assertTrue(self.out["allowedKept"], "allow-listed functions must survive")

    def test_svg_ids_cannot_clobber_page_ids(self):
        self.assertEqual(self.out["byId"], ["FOOTER", "BUTTON", "BUTTON"])
        self.assertGreater(self.out["footText"], 0)
        ids = self.out["svgIds"]
        self.assertTrue(ids and all(re.fullmatch(r"bsvg\d+-[\w.:-]+", i) for i in ids), ids)

    def test_svg_references_follow_their_ids(self):
        target = re.fullmatch(r"url\(#(.+)\)", self.out["marker"]).group(1)
        self.assertIn(target, self.out["svgIds"])
        self.assertTrue(target.endswith("-arr"))

    def test_context_stays_inside_its_script_and_round_trips(self):
        # In the page it is broken as "<\\/SCRIPT" and "<\\!--"; what the reader copies is exact.
        self.assertIn("<\\/SCRIPT><img src=x onerror=", self.out["ctx"])
        self.assertIn("<\\!--<script>", self.out["ctx"])
        self.assertTrue(self.out["copied"].endswith(CONTEXT), self.out["copied"][-120:])

    def test_footer_is_text(self):
        self.assertIn("<img src=x onerror=", self.out["foot"])

    def test_placeholder_in_title_not_refilled(self):
        self.assertEqual(self.out["title"], "attack {{CONTEXT}}")


class EmbedAndVerify(unittest.TestCase):
    def test_embedded_payloads_cannot_close_or_comment_the_script(self):
        j = embed_json({"a": "</SCRIPT><!--<script>"})
        self.assertNotIn("<", j)
        self.assertEqual(json.loads(j)["a"], "</SCRIPT><!--<script>")
        t = embed_text("x </SCRIPT> </script> </Script <!--<script>")
        self.assertIsNone(re.search(r"(?i)</script|<!--", t))

    def test_verify_flags_every_link_attack(self):
        refused = {re.search(r'link "(\w+)"', p).group(1) for p in verify.check_links(packet())}
        self.assertEqual(refused, {"c%d" % i for i in range(1, 12)})   # c11: raw quote

    def test_verify_flags_every_svg_attack(self):
        svg = " ".join(verify.check_svg(packet()))
        for bad in ("<svg onload>", "<image>", "<script>", "<foreignobject>", "<a>", "<animate>",
                    "<set>", "<use href=", "<style>", "url(#", "<img>", "onclick",
                    '<rect style="background:\\75', '<rect fill="\\75', '<rect stroke="u\\72',
                    '<rect style="mask:u\\rl', '<rect id="foot">', '<rect id="next">', '<rect id="prev">',
                    "background:image-set(", "background:-webkit-image-set(", "border-image-source:image-set(",
                    "mask-image:image-set(", "background:element(", "background:paint(",
                    '<rect fill="cross-fade(', "font-family:'http:"):
            self.assertIn(bad, svg, bad)

    def test_reserved_ids_are_the_templates_ids(self):
        ids = set(re.findall(r'\bid="([^"]+)"', (ROOT / "templates" / "packet.html").read_text()))
        self.assertEqual(verify.RESERVED_IDS, ids)
        self.assertTrue({"foot", "next", "prev", "title"} <= ids)

    def test_allow_listed_css_functions_pass(self):
        self.assertEqual(verify.check_svg_markup(
            '<svg><rect transform="translate(1,2) rotate(3) scale(2) matrix(1,0,0,1,0,0) skewX(4)"'
            ' fill="rgb(1,2,3)" stroke="hsla(1,2%,3%,.5)" style="fill:var(--a);width:calc(1px + 2px)"/></svg>'), [])

    def test_text_attributes_may_hold_a_backslash(self):
        self.assertEqual(verify.check_svg_markup('<svg><text data-en="C:\\dir" aria-label="a\\b">t</text></svg>'), [])

    def test_verify_passes_a_clean_svg(self):
        clean = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 9 9" style="font-family:var(--sans)">'
                 '<defs><marker id="m"><path d="M0 0L9 4z"/></marker></defs>'
                 '<path d="M0 0H9" marker-end="url(#m)"/><use href="#m"/><text data-en="a">a</text></svg>')
        self.assertEqual(verify.check_svg_markup(clean), [])


if __name__ == "__main__":
    unittest.main()
