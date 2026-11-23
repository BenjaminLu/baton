"""Links in packet text: templates/packet.html rich() and verify.py agree.

rich() runs under Node (skipped without it); verify.py's check runs in-process.
Run: python3 -m unittest discover -s tests
"""
import json, re, shutil, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from verify import check_links  # noqa: E402

NODE = shutil.which("node")
BREAKOUT = '[x](https://a"onmouseover="alert(1))'


def rich(*texts):
    src = (ROOT / "templates" / "packet.html").read_text()
    parts = [re.search(r"  const E = .*?\n(?=\n)", src, re.S).group(0),
             re.search(r"  const LINK=.*?\n  function rich\(v\)\{.*?\n  \}\n", src, re.S).group(0)]
    js = "\n".join(parts).replace("const ", "var ") + \
        "\nconsole.log(JSON.stringify(" + json.dumps(list(texts)) + ".map(rich)));"
    out = subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def attrs_of_anchors(html):
    """Attribute names on each <a>, parsed the way a browser tokenizes a start tag."""
    from html.parser import HTMLParser
    found = []
    class P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag == "a":
                found.append(dict(attrs))
    P().feed(html)
    return found


@unittest.skipUnless(NODE, "node not installed")
class RichLinks(unittest.TestCase):
    def test_quote_cannot_break_out_of_href(self):
        out, = rich(BREAKOUT)
        anchors = attrs_of_anchors(out)
        self.assertEqual(len(anchors), 1)
        self.assertEqual(set(anchors[0]), {"href", "target", "rel"})
        self.assertEqual(anchors[0]["href"], 'https://a"onmouseover="alert(1')
        self.assertNotIn('"onmouseover', out)

    def test_javascript_and_data_are_plain_text(self):
        for src in ("[x](javascript:alert(1))", "[x](JaVaScRiPt:alert(1))",
                    "[x](data:text/html,<script>alert(1)</script>)", "[x](vbscript:msgbox)",
                    "[x](//evil.example)"):
            out, = rich(src)
            self.assertNotIn("<a", out, src)
            self.assertNotIn("<script", out, src)

    def test_normal_links(self):
        out, = rich("see [the PR](https://github.com/o/r/pull/3?a=1&b=2) and [mail](mailto:a@b.c) "
                    "and [spec](../references/spec.md#kinds)")
        hrefs = [a["href"] for a in attrs_of_anchors(out)]
        self.assertEqual(hrefs, ["https://github.com/o/r/pull/3?a=1&b=2", "mailto:a@b.c",
                                 "../references/spec.md#kinds"])
        self.assertIn('href="https://github.com/o/r/pull/3?a=1&amp;b=2"', out)

    def test_entities_and_markup_stay_text(self):
        out, = rich("a <b>&amp; \"q\" 'r' `x<y` **bold** [l](https://e.x/`a`)")
        self.assertIn("&lt;b&gt;&amp;amp; &quot;q&quot; &#39;r&#39;", out)
        self.assertIn("<code>x&lt;y</code>", out)
        self.assertIn("<strong>bold</strong>", out)
        self.assertIn('href="https://e.x/`a`"', out)   # backticks in a URL do not open <code>


class VerifyLinks(unittest.TestCase):
    def packet(self, text):
        return {"sections": [{"kind": "prose", "text": [{"p": {"en": text}}]}]}

    def test_refused_schemes_fail(self):
        for url in ("javascript:alert(1)", "data:text/html,x", "vbscript:x", "//evil.example"):
            self.assertEqual(len(check_links(self.packet(f"[x]({url})"))), 1, url)

    def test_quote_in_url_fails(self):
        out = check_links(self.packet(BREAKOUT))
        self.assertEqual(len(out), 1)
        self.assertIn("raw quote", out[0])

    def test_normal_links_pass(self):
        self.assertEqual(check_links(self.packet(
            "[a](https://x.y/p?a=1&b=2) [b](mailto:a@b.c) [c](../x.md#s) [d](#top)")), [])


if __name__ == "__main__":
    unittest.main()
