"""verify.py gates. Run: python3 -m unittest discover -s tests"""
import copy, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from verify import check_components  # noqa: E402

CHAIN = {
    "kind": "chain", "heading": {"en": "Retry skips the lock"},
    "nodes": [{"id": "api", "name": {"en": "API"}}, {"id": "q", "name": {"en": "queue"}},
              {"id": "db", "name": {"en": "store"}}],
    "before": {"hot": ["q"], "sub": {"q": "retry()"}, "why": {"at": "q", "text": {"en": "no lock"}},
               "outcome": {"en": "two rows written"}},
    "after": {"hot": ["q"], "sub": {"q": "retry(lock)"}, "why": {"at": "q", "text": {"en": "lock held"}},
              "outcome": {"en": "one row, second call gets `409`"}},
    "proof": [{"type": "test", "label": {"en": "queue_test.go:12"}, "state": "verified"}],
}


def problems_for(proof):
    s = copy.deepcopy(CHAIN)
    s["proof"] = proof
    return [p for p in check_components({"sections": [s]}) if "proof" in p]


class ProofState(unittest.TestCase):
    def test_explicit_states_pass(self):
        for st in ("verified", "code-only", "absent"):
            self.assertEqual(problems_for([{"label": {"en": "x"}, "state": st}]), [], st)

    def test_missing_state_fails(self):
        out = problems_for([{"type": "test", "label": {"en": "queue_test.go:12"}}])
        self.assertEqual(len(out), 1)
        self.assertIn("has no `state`", out[0])
        self.assertIn("queue_test.go:12", out[0])

    def test_null_or_empty_state_fails(self):
        for st in (None, ""):
            self.assertEqual(len(problems_for([{"label": {"en": "x"}, "state": st}])), 1, repr(st))

    def test_unknown_state_fails(self):
        out = problems_for([{"label": {"en": "x"}, "state": "passed"}])
        self.assertEqual(len(out), 1)
        self.assertIn('"passed" is not one of', out[0])


if __name__ == "__main__":
    unittest.main()
