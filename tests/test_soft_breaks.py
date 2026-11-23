"""softBreaks() in templates/packet.html: where a long name may wrap.

Runs the page's own function under Node; skipped where Node is absent.
Run: python3 -m unittest discover -s tests
"""
import json, re, shutil, subprocess, unittest
from pathlib import Path

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "packet.html"
NODE = shutil.which("node")


def soft_breaks(*texts):
    src = TEMPLATE.read_text()
    fn = re.search(r"  const SOFT_RUN=14;.*?join\(''\);", src, re.S).group(0)
    js = fn.replace("const ", "var ") + "\nconsole.log(JSON.stringify(" + \
        json.dumps(list(texts)) + ".map(softBreaks)));"
    out = subprocess.run([NODE, "-e", js], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def pieces(html):
    return re.sub(r"<(?!wbr>)[^>]*>", "", html).split("<wbr>")


@unittest.skipUnless(NODE, "node not installed")
class SoftBreaks(unittest.TestCase):
    def test_camel_case_breaks_at_seams(self):
        out, = soft_breaks("AbstractSingletonProxyFactoryBeanProvider")
        self.assertEqual(pieces(out), ["Abstract", "Singleton", "Proxy", "Factory", "Bean", "Provider"])

    def test_acronym_then_word(self):
        out, = soft_breaks("HTTPServerRequestHandler")
        self.assertEqual(pieces(out), ["HTTP", "Server", "Request", "Handler"])

    def test_run_without_seams_breaks_every_14(self):
        for word in ("ABSTRACTSINGLETONPROXYFACTORYBEANPROVIDER",
                     "abstractsingletonproxyfactorybeanprovider",
                     "96d3ca8f0dc741e1fd308ed6d6d3496f8618aa8f9f12de03031ab7bf5b721cb4"):
            out, = soft_breaks(word)
            ps = pieces(out)
            self.assertEqual("".join(ps), word)
            self.assertTrue(all(len(p) <= 14 for p in ps), ps)
            self.assertGreater(len(ps), 1)

    def test_hash_is_not_split_at_every_digit(self):
        out, = soft_breaks("dcf9f6641cc4d77c13730691d163ea7709814171")
        self.assertEqual([len(p) for p in pieces(out)], [14, 14, 12])

    def test_separators_and_short_words(self):
        out, = soft_breaks("BenjaminLu/baton isPinnedBaton BATON_ADAPTER")
        self.assertEqual(out, "BenjaminLu/<wbr>baton isPinnedBaton BATON_<wbr>ADAPTER")

    def test_tags_and_entities_untouched(self):
        src = '<code class="a_b/c.d">HTTPServerRequestHandler</code> &amp; x'
        out, = soft_breaks(src)
        self.assertIn('<code class="a_b/c.d">', out)
        self.assertIn("&amp; x", out)


if __name__ == "__main__":
    unittest.main()
