"""verify.py § system map: one map, drawn the same by the boundary map,
every runbook, and the architecture / sequence figures of the same state.
Run: python3 -m unittest discover -s tests"""
import copy, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from verify import check_failures, check_system_map  # noqa: E402

E = lambda s: {"en": s}
SVG = ('<svg><text data-en="biz-relay (Rails)">biz-relay (Rails)</text><text data-en="Gateway API">x</text>'
       '<text data-en="FCM / APNs">x</text><text data-en="Ops admin">x</text></svg>')
GOOD = {
    "systems": {"state": "after",
                "systems": [{"id": "br", "name": E("biz-relay")}, {"id": "api", "name": E("Gateway API")},
                            {"id": "fcm", "name": E("FCM / APNs")}],
                "groups": {"gw": {"name": E("Push Gateway"), "parts": ["api"]}}},
    "sections": [
        {"kind": "figure", "heading": E("After"), "view": "architecture", "state": "after", "svg": SVG,
         "context": ["ops"],
         "edges": [{"from": "ops", "to": "br", "evidence": "x"}, {"from": "br", "to": "api", "evidence": "x"},
                   {"from": "api", "to": "fcm", "evidence": "x"}]},
        {"kind": "figure", "heading": E("Today"), "view": "architecture", "state": "before",
         "edges": [{"from": "br", "to": "kafka", "evidence": "x"}]},
        {"kind": "runbook", "heading": E("Runbook — token errors"),
         "rows": [{"at": "api>fcm", "mode": E("UNREGISTERED"), "impact": E("no push"), "action": E("suppress"),
                   "state": "detected", "detect": E("count")}]},
        {"kind": "boundary", "heading": E("Boundary map"), "findings": [], "ok": E("checked")},
    ]}


def run(mut=None):
    d = copy.deepcopy(GOOD)
    if mut:
        mut(d)
    return check_system_map(d)


class SystemMap(unittest.TestCase):
    def test_good_packet_passes(self):
        self.assertEqual(run(), [])

    def test_runbook_as_compare_fails(self):
        def m(d):
            d["sections"].append({"kind": "compare", "heading": E("Runbook — provider errors"),
                                  "cols": [E("code"), E("today"), E("action")], "rows": []})
        self.assertTrue(any("must be a `runbook`" in p for p in run(m)))

    def test_chinese_failure_table_as_compare_fails(self):
        def m(d):
            d["sections"].append({"kind": "compare", "heading": {"en": "Table", "hant": "失效模式"}, "rows": []})
        self.assertTrue(any("must be a `runbook`" in p for p in run(m)))

    def test_figure_without_view_or_state_fails(self):
        def m(d):
            del d["sections"][0]["view"], d["sections"][0]["state"]
        out = run(m)
        self.assertTrue(any("needs `\"view\"" in p for p in out))
        self.assertTrue(any("needs `\"state\"" in p for p in out))

    def test_map_of_today_with_after_figure_fails(self):
        def m(d):
            d["systems"]["state"] = "today"
        self.assertTrue(any("must be \"after\"" in p for p in run(m)))

    def test_after_figure_missing_a_system_fails(self):
        def m(d):
            d["sections"][0]["edges"] = [e for e in d["sections"][0]["edges"] if e["to"] != "fcm"]
        self.assertTrue(any('has "fcm"' in p for p in run(m)))

    def test_after_figure_extra_node_fails(self):
        def m(d):
            d["sections"][0]["edges"].append({"from": "fcm", "to": "kafka", "evidence": "x"})
        self.assertTrue(any('draws "kafka"' in p for p in run(m)))

    def test_group_covers_its_parts(self):
        def m(d):
            d["sections"].append({"kind": "figure", "heading": E("Seq"), "view": "sequence", "state": "after",
                                  "edges": [{"from": "br", "to": "gw", "evidence": "x"},
                                            {"from": "gw", "to": "fcm", "evidence": "x"}]})
        self.assertEqual(run(m), [])

    def test_renamed_label_fails(self):
        def m(d):
            d["sections"][0]["svg"] = d["sections"][0]["svg"].replace("Gateway API", "Sender")
        self.assertTrue(any('labelled "Gateway API"' in p for p in run(m)))

    def test_section_systems_must_equal_map(self):
        def m(d):
            d["sections"][3]["systems"] = [{"id": "br"}, {"id": "kafka"}]
        self.assertTrue(any("differ from the packet map" in p for p in run(m)))

    def test_runbook_row_off_the_map_fails(self):
        def m(d):
            d["sections"][2]["rows"][0]["at"] = "br>fcm"     # not adjacent on the map
        d = copy.deepcopy(GOOD); m(d)
        self.assertTrue(any("not a system id" in p for p in check_failures(d)[0]))

    def test_good_packet_failures_pass(self):
        self.assertEqual(check_failures(copy.deepcopy(GOOD))[0], [])

    def test_boundary_failures_beside_runbooks_fail(self):
        d = copy.deepcopy(GOOD)
        d["sections"][3]["failures"] = copy.deepcopy(d["sections"][2]["rows"])
        self.assertTrue(any("keeps only its pins" in p for p in check_failures(d)[0]))

    def test_same_row_in_two_runbooks_fails(self):
        d = copy.deepcopy(GOOD)
        dup = copy.deepcopy(d["sections"][2]); dup["heading"] = E("Runbook — provider")
        dup["rows"][0]["mode"] = E("`UNREGISTERED` (404) — app gone")
        d["sections"][2]["rows"][0]["mode"] = E("`UNREGISTERED`")
        d["sections"].insert(3, dup)
        self.assertTrue(any("one failure mode, one row" in p for p in check_failures(d)[0]))

    def test_missing_registry_with_two_views_fails(self):
        def m(d):
            del d["systems"]
        self.assertTrue(any("top-level `systems`" in p for p in run(m)))

    def test_more_than_eight_systems_fails(self):
        def m(d):
            d["systems"]["systems"] = [{"id": f"s{i}", "name": E(f"S{i}")} for i in range(9)]
        self.assertTrue(any("at most 8" in p for p in run(m)))


if __name__ == "__main__":
    unittest.main()
