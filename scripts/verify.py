#!/usr/bin/env python3
"""Check a rendered packet for the failures a reader cannot see.

Deliberately small. Diagram correctness is checked by eye in a browser — that
is the gate, and no regex substitutes for it. What a script does better than
eyes is notice an absence: a refusal declaration that was dropped, an
identifier left bare in a sentence written for someone who does not read code.

Usage: verify.py <page>.html [--repo .] [--register eli5|engineer]
"""
import argparse, json, re, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from figures import lazy_after_reason  # noqa: E402  (one rule, shared with the layout)

# An identifier a reader would have to decode. Marked terms (backticks, <code>)
# and glossary entries are exempt — see the register rule in pipeline.md §4.
IDENTIFIER = re.compile(
    r"\b[a-z0-9]+_[a-z0-9_]+\b"                 # snake_case
    r"|\b[A-Z][A-Z0-9]*_[A-Z0-9_]+\b"           # UPPER_SNAKE, usually a state
    # camelCase and PascalCase need a lowercase run before the inner capital,
    # or an ordinary shouted word like CHANGED matches and the checker starts
    # rejecting its own labels.
    r"|\b[a-z][a-z0-9]+[A-Z][A-Za-z]*\b"
    r"|\b[A-Z][a-z0-9]+[A-Z][A-Za-z]*\b"
    r"|\b[A-Za-z_][\w.]*\.(?:go|rs|py|rb|ts|tsx|js|java|kt|sql|json|ya?ml)\b"
    r"|\b\w+/\w+/[\w./]+"                       # paths
    r"|::"
    r"|\b[0-9a-f]{7,40}\b")                     # sha

TERM_MARKUP = re.compile(r"<(code|kbd|samp)\b[^>]*>.*?</\1>", re.S | re.I)
REFUSAL = ("say you do not know", "say you don't know", "說不知道", "说不知道")

# Keys whose values are data, not reader-facing prose: mermaid source, ids,
# database column names shown as data, and the glossary itself — scanning the
# glossary flags the very words it exists to permit.
SKIP_KEYS = {"mermaid", "svg", "id", "kind", "tone", "filename", "range",
             "repo", "branch", "format_version", "layer", "glossary",
             "layer_note", "k", "was", "now", "method", "table", "op",
             "guard", "summary", "ref", "at", "state", "failure"}


def load(path):
    html = Path(path).read_text()
    m = re.search(r'<script id="baton-data"[^>]*>(.*?)</script>', html, re.S)
    data = None
    if m:
        try:
            data = json.loads(m.group(1).replace("<\\/", "</"))
        except json.JSONDecodeError:
            pass
    return html, data


def prose(data):
    """Every reader-facing string in the packet, with where it came from."""
    out = []
    def walk(v, path="data"):
        if isinstance(v, str):
            out.append((path, v))
        elif isinstance(v, dict):
            for k, x in v.items():
                if k not in SKIP_KEYS:
                    walk(x, f"{path}.{k}")
        elif isinstance(v, list):
            for x in v:
                walk(x, path)
    if data:
        walk(data)
    return [(w, t) for w, t in out if t]


def check_register(data, glossary=()):
    """Catch words the reader has to decode, not words that are technical.

    A page about a database has to say `payments` and `status_log` — the most
    precise words available, and translating them costs the reader the word
    they need with an engineer afterwards. What breaks a page is an identifier
    dropped into prose with nothing marking it as a name.
    """
    allowed = {g.lower() for g in glossary}
    problems = []
    for where, text in prose(data):
        clean = TERM_MARKUP.sub(" ", text)
        clean = re.sub(r"`[^`]+`", " ", clean)   # backticks render as <code>
        for m in IDENTIFIER.finditer(clean):
            if m.group(0).lower() in allowed:
                continue
            problems.append(
                f'{where}: "{m.group(0)}" is unmarked code in a sentence — '
                f'mark it as a term or find a word — in: {text[:70]}')
    return problems


def check_context(html):
    m = re.search(r'<script id="baton-context"[^>]*>(.*?)</script>', html, re.S)
    if not m:
        return ["no embedded context; the page is a summary with nothing behind it"]
    ctx = m.group(1)
    if not any(r in ctx.lower() for r in REFUSAL):
        return ["context is missing its refusal declaration; a receiving agent "
                "will fill gaps by inference instead of saying it does not know"]
    if len(ctx) < 2000:
        return [f"context is {len(ctx)} characters — that is a digest, not the "
                "complete three-layer context (pipeline §2)"]
    return []


CONCRETE = re.compile(r"`[^`]+`|\d|\"[^\"]+\"|「[^」]+」|“[^”]+”")
SVG_OUTCOME = re.compile(
    r'data-node="(before|after)-outcome".*?<text[^>]*data-en="([^"]*)"[^>]*data-hant="([^"]*)"', re.S)


def _langs(v):
    if isinstance(v, dict):
        return v.get("en", ""), v.get("hant", v.get("en", ""))
    return (v or ""), (v or "")


def check_before_after(data):
    """The gate against lazy before/after (diagrams.md § Per-change before / after).

    A card that says only "the old problem is gone" tells the reader nothing
    they could not have guessed from the title. Every change card must state
    what the system did BEFORE and what it does AFTER — observable, concrete,
    and the AFTER may not be the BEFORE with a negation bolted on.
    """
    problems = []
    for idx, s in enumerate((data or {}).get("sections", [])):
        # chain sections carry structured before/after rows; check_components owns them
        if s.get("kind") == "chain":
            continue
        is_card = s.get("kind") == "vuln"
        has_pair = "before" in s or "after" in s
        if not (is_card or has_pair):
            continue
        name = _langs(s.get("heading"))[0] or f"section {idx}"
        if not s.get("before") or not s.get("after"):
            problems.append(f'"{name}": change card has no `before` / `after` — state what the '
                            "system did and what it does now (spec.md § vuln)")
            continue
        for lang, b, a in zip(("en", "hant"), _langs(s["before"]), _langs(s["after"])):
            r = lazy_after_reason(b, a)
            if r:
                problems.append(f'"{name}" [{lang}]: {r}')
            elif not CONCRETE.search(a):
                problems.append(f'"{name}" [{lang}]: AFTER is not concrete — name the new value, '
                                "error, state or call (a `code` term, a number or a quoted value): " + a[:80])
        svg = s.get("svg")
        if svg:
            found = {k: (en, hant) for k, en, hant in SVG_OUTCOME.findall(svg)}
            if set(found) != {"before", "after"}:
                problems.append(f'"{name}": figure lacks data-node="before-outcome" and '
                                '"after-outcome" boxes — draw it with scripts/figures.py before_after()')
            else:
                for lang in (0, 1):
                    r = lazy_after_reason(found["before"][lang], found["after"][lang])
                    if r:
                        problems.append(f'"{name}" figure: {r}')
            if re.search(r'data-node="after-outcome"[^>]*stroke-dasharray', svg) or "✗" in svg:
                problems.append(f'"{name}" figure: AFTER outcome is drawn struck-through / ✗ — '
                                "draw the new outcome as a live box instead")
    return problems


LENSES = {"identity", "truth", "effect", "dependency", "coexist", "edges"}
MARKS = {"have", "part", "gap", "plan", "na"}
PROOF_STATES = {"verified", "code-only", "absent"}


def _en(v):
    if isinstance(v, dict):
        return str(v.get("en") or "")
    return "" if v is None else str(v)


def _ids(nodes):
    return {n.get("id") for n in nodes or []}


def check_components(data):
    """Every section is a component, not a slab of text (spec.md § Section kinds).

    The page exists to be read in minutes. A section that is mostly sentences,
    a list of findings typed as lines, or a three-box change card all read as
    plain text — which is the thing this format replaces.
    """
    problems = []
    for i, s in enumerate((data or {}).get("sections") or []):
        name = _en(s.get("heading")) or f"section {i+1}"
        k = s.get("kind") or "prose"
        if k == "vuln":
            problems.append(f'"{name}": kind "vuln" is retired — draw the change as a "chain" '
                            "(the real component chain before/after, with proof)")
        elif k == "points":
            if s.get("role") != "questions":
                problems.append(f'"{name}": a "points" list reads as plain text — findings and risks go '
                                'in "chain" cards or the "boundary" map; points are only for '
                                '"role": "questions"')
            items = s.get("items") or []
            if len(items) > 6:
                problems.append(f'"{name}": {len(items)} open questions — keep the 6 that block most')
            for it in items:
                if len(_en(it.get("text"))) > 200:
                    problems.append(f'"{name}": an open question over 200 characters — one question, one sentence')
        elif k == "prose":
            blocks = s.get("text")
            blocks = blocks if isinstance(blocks, list) else [{"p": blocks}]
            chars = sum(len(_en(b.get("p"))) + len(_en(b.get("note"))) for b in blocks if isinstance(b, dict))
            paras = sum(1 for b in blocks if isinstance(b, dict) and (b.get("p") is not None or b.get("note") is not None))
            visual = any(isinstance(b, dict) and (b.get("stats") or b.get("bars")) for b in blocks)
            if chars > 480 or paras > 3:
                problems.append(f'"{name}": {chars} characters in {paras} paragraphs — turn it into a component '
                                "(chain / compare / matrix / steps / stats) or cut to a two-sentence lead")
            elif not visual and chars > 300:
                problems.append(f'"{name}": prose with no visual — add a stats row or move it into a component')
            for b in blocks:
                if isinstance(b, dict) and b.get("kv") and len(b["kv"]) > 6:
                    problems.append(f'"{name}": a {len(b["kv"])}-row key/value list — use a "compare" or '
                                    '"matrix" section instead')
        elif k == "chain":
            nodes = s.get("nodes") or []
            ids = _ids(nodes)
            if not 3 <= len(nodes) <= 6:
                problems.append(f'"{name}": a chain needs 3–6 real components, has {len(nodes)}')
            for key in ("before", "after"):
                row = s.get(key) or {}
                hot = set(row.get("hot") or [])
                if not hot or not hot <= ids:
                    problems.append(f'"{name}" {key}: mark the {"broken" if key=="before" else "changed"} '
                                    "node(s) in `hot` using node ids")
                why = row.get("why") or {}
                if why.get("at") not in hot or not _en(why.get("text")):
                    problems.append(f'"{name}" {key}: `why` must sit on a hot node and say why that hop '
                                    "produces the outcome")
                if not _en(row.get("outcome")):
                    problems.append(f'"{name}" {key}: no outcome')
                missing = [n.get("id") for n in nodes if n.get("id") in hot and not (row.get("sub") or {}).get(n.get("id"))]
                if missing:
                    problems.append(f'"{name}" {key}: hot node(s) {missing} carry no mechanism (`sub`)')
            for lang in ("en", "hant"):
                bo = ((s.get("before") or {}).get("outcome") or {})
                ao = ((s.get("after") or {}).get("outcome") or {})
                bo = bo.get(lang) if isinstance(bo, dict) else bo
                ao = ao.get(lang) if isinstance(ao, dict) else ao
                r = lazy_after_reason(bo or "", ao or "")
                if r:
                    problems.append(f'"{name}" [{lang}]: {r}')
            for key in ("before", "after"):
                row = s.get(key) or {}
                for nid, v in (row.get("sub") or {}).items():
                    if isinstance(v, str) and len(v) > 24:
                        problems.append(f'"{name}" {key}.{nid}: code label "{v}" is {len(v)} chars — '
                                        "keep code labels ≤ 24 so they do not break mid-token")
                for hi, v in (row.get("hops") or {}).items():
                    t = v if isinstance(v, str) else _en(v)
                    if len(t) > 16:
                        problems.append(f'"{name}" {key}.hop{hi}: "{t}" is {len(t)} chars — hop labels ≤ 16')
            proof = s.get("proof") or []
            if not proof:
                problems.append(f'"{name}": no proof — list the tests, CI runs, live checks or reproductions '
                                'that show the AFTER, with "state": verified | code-only | absent')
            for pr in proof:
                # No default: a chip whose author never said what it proves must
                # not read as verified (or as anything else) by omission.
                label = _en(pr.get("label"))[:50] or "(no label)"
                if "state" not in pr or pr.get("state") in (None, ""):
                    problems.append(f'"{name}": proof chip "{label}" has no `state` — set it explicitly to '
                                    f'one of {sorted(PROOF_STATES)}; a missing state is never read as verified')
                elif pr["state"] not in PROOF_STATES:
                    problems.append(f'"{name}": proof chip "{label}" state "{pr["state"]}" is not one of '
                                    f'{sorted(PROOF_STATES)}')
        elif k == "compare":
            rows = s.get("rows") or []
            if len(rows) > 6:
                problems.append(f'"{name}": {len(rows)} compare rows — split, never shrink (max 6)')
            if any(len(r) != 3 for r in rows):
                problems.append(f'"{name}": every compare row is [dimension, from, to]')
        elif k == "matrix":
            cols = s.get("cols") or []
            for r in s.get("rows") or []:
                v = r.get("v") or []
                if len(v) != len(cols) or not set(v) <= MARKS:
                    problems.append(f'"{name}": matrix row "{_en(r.get("k"))}" must hold one of '
                                    f"{sorted(MARKS)} per column")
            if len(s.get("rows") or []) > 12:
                problems.append(f'"{name}": more than 12 matrix rows — split it')
        elif k == "chart":
            t = s.get("type")
            ser = s.get("series") or []
            n = len(s.get("x") or [])
            if t not in ("line", "bar", "stacked", "funnel"):
                problems.append(f'"{name}": chart type "{t}" is not line | bar | stacked | funnel')
            if not _en(s.get("source")):
                problems.append(f'"{name}": a chart without `source` is a number nobody can check — '
                                "name the query, dashboard or file the data came from")
            if not ser or len(ser) > 4 or (t == "funnel" and len(ser) != 1):
                problems.append(f'"{name}": {len(ser)} series — charts carry 1–4 (funnel exactly 1); '
                                "fold the rest into Other or split into small multiples")
            for se in ser:
                vals = se.get("values") or []
                if len(vals) != n or not all(isinstance(v, (int, float)) for v in vals):
                    problems.append(f'"{name}": series "{_en(se.get("name"))}" needs {n} numeric values')
            if s.get("y2") or s.get("unit2"):
                problems.append(f'"{name}": a second axis — split into two charts instead')
        elif k == "steps":
            if not 3 <= len(s.get("steps") or []) <= 5:
                problems.append(f'"{name}": steps hold 3–5 items')
    return problems


def check_boundary_review(html, data):
    """The last section is the boundary map (boundary-review.md)."""
    sections = (data or {}).get("sections") or []
    if not sections or sections[-1].get("kind") != "boundary":
        return ['the last section must be the boundary map — kind "boundary" '
                "(references/boundary-review.md); with no finding it carries `ok`, "
                "saying what was checked"]
    sec = sections[-1]
    problems = []
    ids = _ids(sec.get("systems"))
    if len(ids) < 2:
        problems.append("the boundary map needs at least two systems")
    chains = {_en(s.get("heading")) for s in sections if s.get("kind") == "chain"}
    finds = sec.get("findings") or []
    for f in finds:
        at = str(f.get("at", ""))
        ends = at.split(">") if ">" in at else [at]
        if not all(e in ids for e in ends):
            problems.append(f'boundary finding {f.get("n")}: `at` "{at}" is not a system id or "a>b" link')
        if f.get("lens") not in LENSES:
            problems.append(f'boundary finding {f.get("n")}: lens "{f.get("lens")}" is not one of {sorted(LENSES)}')
        if f.get("card") not in chains:
            problems.append(f'boundary finding {f.get("n")}: `card` must name the chain card that draws it')
    if not finds and not _en(sec.get("ok")):
        problems.append("a boundary map with no finding must say what was checked in `ok`")
    if finds and sec.get("ok"):
        problems.append("`ok` must stand alone — drop it or the findings")
    m = re.search(r'<script id="baton-context"[^>]*>(.*?)</script>', html, re.S)
    if m and "## Boundary review" not in m.group(1):
        problems.append('context lacks a "## Boundary review" heading in layer (b) — record the '
                        "boundaries checked, each lens's result, and dropped candidates")
    return problems


FAILURE_STATES = {"handled", "detected", "unhandled"}
GITHUB_CODE = re.compile(r"(?ai)^https://(?:www\.)?github\.com/[^/?#]+/[^/?#]+/(?:blob|blame|tree|raw|edit|commits|history)/")
GITHUB_HOST = re.compile(r"(?ai)^https://(?:(?:www\.)?github\.com|raw\.github(?:usercontent)?\.com|"
                         r"media\.githubusercontent\.com)(?=[/?#]|$)")
GITHUB_RAW = re.compile(r"(?ai)^https://(?:raw\.github(?:usercontent)?\.com|media\.githubusercontent\.com/media)"
                        r"/[^/?#]+/[^/?#]+/([^/?#]+)/")
GITHUB_BLOB = re.compile(r"(?ai)^https://(?:www\.)?github\.com/([^/?#]+/[^/?#]+)/(?:blob|blame|raw)/([^/?#]+)/[^#]+"
                         r"(#L\d+(?:C\d+)?(?:-L\d+(?:C\d+)?)?)?$")


REF_HOST = re.compile(r"(?ai)^https://[a-z0-9-]+(?:\.[a-z0-9-]+)*(?=[/?#]|$)")
DOT_SEG = re.compile(r"(?ai)/(?:\.|%2e){1,2}(?=[/?#]|$)")
# The path is matched from a fixed point after the host, so a long host
# cannot make these backtrack quadratically.
EMPTY_SEG = re.compile(r"(?ai)^https://[^/?#]+(?:/[^?#]*)?//")       # GitHub folds // away
GITHUB_ESC = re.compile(r"(?ai)^https://[^/?#]+(?:/[^?#%]*)?%")       # and decodes %xx in the path
REF_MAX = 2048


def safe_ref(url):
    """A failure mode's evidence link: https only, no control character or
    space, no raw quote / angle bracket / backtick (the page's safeRef())."""
    if not isinstance(url, str) or len(url) > REF_MAX or safe_href(url) is None or not re.match(r"(?ai)^https://", url):
        return None
    # The host shown must be the host opened (the page's REF_HOST / DOT_SEG):
    # ASCII labels only, no port, trailing dot, userinfo or percent-escape; no
    # backslash; no dot segment that would fold /blob/<sha>/../main/ away.
    if re.search(r"[\"'<>`\\]", url) or not REF_HOST.match(url) or DOT_SEG.search(url):
        return None
    # GitHub serves /o//r/blob/… and /o/r/bl%6fb/… as the plain path, which would
    # slip a fork or a branch past the pin check and the owner/repo label.
    if EMPTY_SEG.search(url) or (GITHUB_HOST.match(url) and GITHUB_ESC.search(url)):
        return None
    return url


def _js_str(v):
    """String(v) as the page computes it, so an id compares the same here."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _text(v):
    """Text the page would print for an i18n field: a string or an i18n dict."""
    if isinstance(v, dict):
        return v["en"] if isinstance(v.get("en"), str) else ""
    return v if isinstance(v, str) else ""


def _sys_id(n):
    """A system's id as the page prints it: String(undefined) when it has none."""
    return _js_str(n["id"]) if "id" in n else "undefined"


def _links(systems):
    """The links the map draws, as (key, a, b): each system to the next one."""
    ids = [_sys_id(n) for n in systems or [] if isinstance(n, dict)]
    return [(f"{a}>{b}", a, b) for a, b in zip(ids, ids[1:])]


# A failure id is an anchor and a key: short, ASCII, no space. A row written
# before ids existed gets "#<n>", n its place in the table as drawn — a
# character no authored id may hold, so it can never collide with one or be
# cited by a runbook row.
FAILURE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
RUNBOOK_FIELDS = ("detect", "impact", "action")


def runbook_of(sec):
    """The failure modes and the runbook rows of a boundary section, as the
    page draws them (templates/packet.html failureModel()).

    Returns (modes, rows). `modes` is [(index, row, id, authored)] for every
    object in `failures`; `rows` is [(index | None, row, [cited ids])] for every
    runbook row, with a row generated — `index` None — for each mode that
    still carries detect / impact / action itself and no runbook row cites.
    """
    fails = sec.get("failures") if isinstance(sec.get("failures"), list) else []
    book = sec.get("runbook") if isinstance(sec.get("runbook"), list) else []
    modes = []
    for i, f in enumerate(fails):
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        modes.append([i, f, fid, True] if isinstance(fid, str) and FAILURE_ID.fullmatch(fid) else [i, f, None, False])
    # Number the rows without an id as the page draws the table: boundary by
    # boundary in map order, worst first inside one, then packet order.
    order = []
    for a in (sec.get("systems") if isinstance(sec.get("systems"), list) else []):
        if isinstance(a, dict):
            order.append(_sys_id(a))
    keys = []
    for k, a in enumerate(order):
        keys.append(a)
        if k + 1 < len(order):
            keys.append(f"{a}>{order[k+1]}")
    pos = lambda at: keys.index(at) if at in keys else 10**9
    rank = lambda st: {"unhandled": 0, "detected": 1, "handled": 2}.get(st, -1) if isinstance(st, str) else -1
    at_of = lambda f: "" if f.get("at") is None else _js_str(f.get("at"))
    for n, m in enumerate(sorted(modes, key=lambda m: (pos(at_of(m[1])), rank(m[1].get("state")), m[0]))):
        if not m[3]:
            m[2] = f"#{n+1}"
    modes = [tuple(m) for m in modes]
    rows, cited = [], set()
    for i, r in enumerate(book):
        if not isinstance(r, dict):
            continue
        ids = _cites(r)
        cited.update(ids)
        rows.append((i, r, ids))
    for _, f, fid, authored in modes:
        if (not authored or fid not in cited) and any(k in f for k in RUNBOOK_FIELDS):
            rows.append((None, {k: f[k] for k in RUNBOOK_FIELDS if k in f}, [fid]))
    return modes, rows


def _cites(r):
    """The failure ids a runbook row names in `failure`: one id or a list."""
    v = r.get("failure")
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [x for x in v if isinstance(x, str)]
    return []


def check_failures(data, register="engineer"):
    """The failure-mode list on the boundary map and its runbook
    (boundary-review.md §3).

    One home per fact: a failure mode on the map is id · at · mode · state ·
    evidence; what detects it, what the user sees and what to do live in one
    runbook row that cites the id. Returns (problems, warnings). Problems fail
    the run; warnings print and leave the exit code alone. A packet written
    before ids and the runbook existed renders unchanged (the page moves the
    fields into generated runbook rows) and gets warnings saying how to
    migrate, never a failure or a traceback.
    """
    sections = (data or {}).get("sections") if isinstance(data, dict) else None
    if not isinstance(sections, list) or not sections or not isinstance(sections[-1], dict) \
            or sections[-1].get("kind") != "boundary":
        return [], []          # check_boundary_review already reports the missing map
    sec = sections[-1]
    problems, warnings = [], []
    systems = sec.get("systems") if isinstance(sec.get("systems"), list) else []
    ids = {_sys_id(n) for n in systems if isinstance(n, dict)}
    for i in sorted(i for i in ids if ">" in i):
        problems.append(f'system id "{i[:40]}" contains ">" — it would make an `at` link ambiguous; rename it')
    if "failures" not in sec:
        msg = ("the boundary map has no `failures` — list every failure mode per system and link "
               "(id, at, mode, state, ref; boundary-review.md §3) with a `runbook` row per mode, or "
               '`"failures": []` when none apply')
        (problems if register == "engineer" and len(ids) >= 2 else warnings).append(msg)
        return problems, warnings
    rows = sec.get("failures")
    if not isinstance(rows, list):
        return ["`failures` must be a list of failure modes"], warnings
    if "runbook" in sec and not isinstance(sec.get("runbook"), list):
        return ["`runbook` must be a list of runbook rows"], warnings
    hashable = lambda v: isinstance(v, (int, str)) and not isinstance(v, bool)
    finds = sec.get("findings") if isinstance(sec.get("findings"), list) else []
    pins = {f.get("n"): ("" if f.get("at") is None else _js_str(f.get("at")))
            for f in finds if isinstance(f, dict) and hashable(f.get("n"))}
    covered = set()
    drawn = {k for k, _, _ in _links(systems)}
    modes, book = runbook_of(sec)
    authored = {fid for _, _, fid, a in modes if a}
    by_id = {}
    for i, f, fid, _ in modes:
        by_id.setdefault(fid, (i, f))          # the first, as the page resolves it
    label_of = lambda i, f, fid: (f'failure mode {i+1}' + (f' `{fid}`' if not fid.startswith("#") else f" ({fid} on the page)") +
                                  f' ("{_en(f.get("mode"))[:40]}")')
    # Which runbook rows name each mode, and what each row says.
    rows_for = {fid: [] for _, _, fid, _ in modes}
    for j, (ri, r, cites) in enumerate(book):
        for c in dict.fromkeys(cites):         # a row counts once, however often it names the id
            if c in rows_for and (c in authored or ri is None):
                rows_for[c].append(j)
    for i, f in enumerate(rows):
        if not isinstance(f, dict):
            problems.append(f"failure mode {i+1}: must be an object")
    seen, legacy_ids, legacy_fields = {}, [], []
    for i, f, fid, is_authored in modes:
        label = label_of(i, f, fid)
        raw = f.get("id")
        if raw is None:
            legacy_ids.append(f"{i+1} = {fid}")
        elif not is_authored:
            problems.append(f"{label}: `id` {str(raw)[:40]!r} must be 1–64 characters of A–Z a–z 0–9 _ . - "
                            "starting with a letter or digit")
        elif fid in seen:
            problems.append(f"{label}: `id` \"{fid}\" is also failure mode {seen[fid]+1} — ids are unique")
        else:
            seen[fid] = i
        at = f.get("at")
        at = _js_str(at) if isinstance(at, (str, int)) and not isinstance(at, bool) else ""
        if not (at in ids or at in drawn):
            problems.append(f'{label}: `at` "{at}" is not a system id or an "a>b" link drawn on the map '
                            "(each system to the next, in map order)")
        else:
            covered.add(at)
        if not _text(f.get("mode")).strip():
            problems.append(f"{label}: `mode` is required")
        own = [k for k in RUNBOOK_FIELDS if k in f]
        cited_by = [j for j in rows_for.get(fid, []) if book[j][0] is not None]
        if own and cited_by:
            problems.append(f"{label}: {', '.join('`'+k+'`' for k in own)} written here and in the runbook row "
                            "that cites it — one home per fact: keep them in the runbook row only")
        elif own:
            legacy_fields.append(fid if is_authored else f"{i+1} = {fid}")
        n_rows = len(rows_for.get(fid, []))
        if n_rows == 0:
            problems.append(f"{label}: no runbook row — add one to `runbook` with "
                            f'"failure": "{fid if is_authored else "<this mode's id>"}" and its detect, impact, action')
        elif n_rows > 1:
            problems.append(f"{label}: {n_rows} runbook rows cite it — each failure mode has exactly one")
        st = f.get("state")
        if st in (None, ""):
            problems.append(f"{label}: no `state` — set one of {sorted(FAILURE_STATES)}; there is no default")
        elif not isinstance(st, str) or st not in FAILURE_STATES:
            problems.append(f'{label}: state "{st}" is not one of {sorted(FAILURE_STATES)}')
        ref = f.get("ref")
        if ref is not None:
            if safe_ref(ref) is None:
                problems.append(f"{label}: `ref` {str(ref)[:60]!r} is not a plain https:// URL — the page "
                                "refuses it: https only, at most 2048 characters; an ASCII host with no port, trailing dot, userinfo or %; no control "
                                "character, space, quote or backslash; no empty, . or .. segment; no % in a GitHub path")
            else:
                m = GITHUB_BLOB.match(ref)
                raw_gh = GITHUB_RAW.match(ref)
                if raw_gh and not re.fullmatch(r"(?ai)[0-9a-f]{7,40}", raw_gh.group(1)):
                    problems.append(f"{label}: `ref` is a raw GitHub link not pinned to a commit — use "
                                    "raw.githubusercontent.com/<owner>/<repo>/<sha>/<path>")
                if GITHUB_CODE.match(ref):
                    if not m:
                        problems.append(f"{label}: `ref` is not a GitHub file permalink — use "
                                        "/blob/<sha>/<path>#La-Lb")
                    elif not re.fullmatch(r"(?ai)[0-9a-f]{7,40}", m.group(2)):
                        problems.append(f"{label}: `ref` is a GitHub link not pinned to a commit — use "
                                        "/blob/<sha>/<path>#La-Lb; a branch link drifts")
                    elif not m.group(3):
                        warnings.append(f"{label}: `ref` names a file but no lines — add #La-Lb")
        if st == "handled" and ref is None and not _text(f.get("source")).strip():
            problems.append(f"{label}: `handled` needs `ref` — the code line that handles it "
                            "(or, on a proposal, the `source` sentence)")
        if st == "detected" and n_rows and not any(_text(book[j][1].get("detect")).strip()
                                                    for j in rows_for[fid]):
            problems.append(f"{label}: `detected` needs `detect` in its runbook row — the signal that notices it")
        if f.get("finding") is not None:
            if not (hashable(f["finding"]) and f["finding"] in pins):
                problems.append(f"{label}: `finding` {f['finding']!r} is not a pin on the map")
            elif pins[f["finding"]] != at:
                problems.append(f'{label}: `finding` {f["finding"]} is pinned at "{pins[f["finding"]]}", '
                                f'not at this row\'s "{at}" — point it at the pin on the same boundary')
        if f.get("introduced") and st == "unhandled" and f.get("finding") is None:
            problems.append(f"{label}: unhandled and introduced by this work — that is a finding; "
                            "give it a pin and set `finding` to its number")
    # The runbook rows themselves.
    raw_book = sec.get("runbook") if isinstance(sec.get("runbook"), list) else []
    for j, r in enumerate(raw_book):
        if not isinstance(r, dict):
            problems.append(f"runbook row {j+1}: must be an object")
    quiet = []
    for ri, r, cites in book:
        name = (f"runbook row {ri+1}" if ri is not None else
                f"failure mode {by_id[cites[0]][0]+1}" + (f" `{cites[0]}`" if not cites[0].startswith("#") else ""))
        if ri is not None:
            v = r.get("failure")
            if v is not None and (not cites or len(cites) != (len(v) if isinstance(v, list) else 1)):
                problems.append(f"{name}: `failure` must be a failure id or a list of them")
            for c in cites:
                if c not in authored:
                    problems.append(f'{name}: cites failure "{c[:40]}", which no failure mode on the map has as its `id`')
            if len(set(cites)) != len(cites):
                problems.append(f"{name}: cites the same failure id twice")
            if not cites and not _text(r.get("symptom")).strip():
                problems.append(f"{name}: cites no failure id and has no `symptom` — say what on-call sees, "
                                'or set "failure" to the id it handles')
        for key in ("impact", "action"):
            if not _text(r.get(key)).strip():
                problems.append(f"{name}: `{key}` is required")
        if not _text(r.get("detect")).strip():
            quiet.append(cites[0] if len(cites) == 1 else (", ".join(cites) or f"row {ri+1}"))
    if legacy_ids:
        warnings.append(f"{len(legacy_ids)} failure mode(s) have no `id` (mode {', '.join(map(str, legacy_ids[:8]))}"
                        f"{' …' if len(legacy_ids) > 8 else ''}) — the page numbers them; migrate: give each an id "
                        "so its runbook row can cite it")
    if legacy_fields:
        warnings.append(f"{len(legacy_fields)} failure mode(s) carry detect / impact / action on the map "
                        f"({', '.join(legacy_fields[:8])}{' …' if len(legacy_fields) > 8 else ''}) — the page moves them "
                        'into the runbook; migrate: write them once in a `runbook` row with "failure": "<id>"')
    if quiet:
        warnings.append(f"no signal today for {len(quiet)} runbook row(s): {', '.join(q[:40] for q in quiet[:8])}"
                        f"{' …' if len(quiet) > 8 else ''} — nothing fires before a user notices; if this work "
                        "opened that gap it is a finding")
    if not _en(sec.get("ok")):
        for link, a, b in _links(systems):
            if not covered & {link, a, b}:
                warnings.append(f'link "{link}" has no failure mode listed — list how it fails' +
                                ("" if sec.get("findings") else ", or say in `ok` why nothing can"))
    return problems, warnings


# The page's link rule (templates/packet.html rich() / safeHref()), mirrored:
# default-deny. Only http(s):// and mailto: render as links, and a URL with
# any control character or space is refused, because browsers strip leading
# C0 controls ("\x01javascript:" runs as javascript:). A packet carrying a
# refused link is an attack or a broken link, so it fails here.
LINK = re.compile(r"\[([^\]\n]+)\]\(([^)\t\n\x0b\f\r ]+)\)")   # same class as the page


def safe_href(url):
    if re.search(r"[\x00-\x20\x7f]", url):
        return None
    return url if re.match(r"(?ai)^(https?://|mailto:)", url) else None   # ASCII, like the page's /i


# The page's SVG allow-list (templates/packet.html safeSVG()), mirrored, so a
# diagram the page would strip fails here instead of silently losing parts.
SVG_OK = {"svg", "g", "path", "rect", "circle", "ellipse", "line", "polyline", "polygon", "text",
          "tspan", "defs", "marker", "title", "desc", "lineargradient", "radialgradient", "stop",
          "clippath", "mask", "pattern", "use"}
LOCAL_URL = re.compile(r"""(?i)url\(\s*['"]?#[\w.:-]+['"]?\s*\)""")
BAD_STYLE = re.compile(r"(?i)expression\s*\(|@import|javascript:|behavior\s*:|-moz-binding")


# Ids the page itself uses (getElementById targets). The page prefixes every
# diagram id, so a collision cannot clobber them any more, but a diagram that
# names one is a probe or a mistake. Read from the template, so the list
# cannot drift from it.
TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "packet.html"
RESERVED_IDS = set(re.findall(r'\bid="([^"]+)"', TEMPLATE.read_text())) if TEMPLATE.exists() else set()


def _text_attr(name):
    return name.startswith(("data-", "aria-")) and name not in ("aria-labelledby", "aria-describedby")


CSS_FN = {"url", "var", "calc", "rgb", "rgba", "hsl", "hsla", "translate", "translatex", "translatey",
          "rotate", "scale", "scalex", "scaley", "matrix", "skewx", "skewy"}
URL_STRING = re.compile(r"""(["'])[^"']*(:|//)[^"']*\1""")


def _url_ok(v):
    """The page's cssOK(): url() only as url(#id), only allow-listed CSS
    functions (image-set(), element(), paint() … fetch without url()), and no
    quoted string holding a URL."""
    if re.search(r"(?i)url\s*\(", LOCAL_URL.sub("", v)):
        return False
    if any(m.group(1).lower() not in CSS_FN for m in re.finditer(r"(?i)(-?[a-z_][\w-]*)\s*\(", v)):
        return False
    return not URL_STRING.search(v)


def check_svg_markup(svg):
    from html.parser import HTMLParser
    found = []
    class P(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag not in SVG_OK:
                found.append(f"<{tag}> is not an allowed SVG element")
                return
            href = None
            for name, value in attrs:
                value = value or ""
                if name == "id" and value in RESERVED_IDS:
                    found.append(f'<{tag} id="{value}">: the page uses that id — rename it')
                if "\\" in value and not _text_attr(name):
                    found.append(f'<{tag} {name}="{value[:40]}">: a backslash can hide a CSS escape '
                                 "(\\75 rl( spells url() — drop it")
                    continue
                if name.startswith("on"):
                    found.append(f"<{tag} {name}>: event handlers are not allowed")
                elif name in ("href", "xlink:href"):
                    href = value
                    if not re.fullmatch(r"#[\w.:-]+", value):
                        found.append(f'<{tag} {name}="{value[:40]}">: only #fragment links are allowed')
                elif name == "style" and (not _url_ok(value) or BAD_STYLE.search(value)):
                    found.append(f'<{tag} style="{value[:40]}">: only url(#…), allow-listed CSS functions '
                                 "and plain values are allowed")
                elif name != "style" and not _text_attr(name) and not _url_ok(value):
                    found.append(f'<{tag} {name}="{value[:40]}">: only url(#…) and allow-listed CSS '
                                 "functions (var, calc, rgb, hsl, transforms) are allowed")
            if tag == "use" and not (href or "").startswith("#"):
                found.append("<use> must point at a #fragment")
        handle_startendtag = handle_starttag
    P().feed(svg)
    return list(dict.fromkeys(found))


def check_svg(data):
    problems = []
    for i, sec in enumerate((data or {}).get("sections") or []):
        if isinstance(sec.get("svg"), str):
            name = _en(sec.get("heading")) or f"section {i+1}"
            problems += [f'"{name}" svg: {p}' for p in check_svg_markup(sec["svg"])]
    return problems


def check_links(data):
    problems = []
    def walk(v, path="data"):
        if isinstance(v, str):
            for m in LINK.finditer(v):
                url = m.group(2)
                if safe_href(url) is None:
                    problems.append(f'{path}: link "{m.group(1)[:30]}" → "{url[:60]!r}" is refused by the '
                                    "page — only http(s):// and mailto: links render, with no control "
                                    "characters or spaces")
                elif re.search(r"[\"'<>`]", url):
                    # The page escapes these, so nothing breaks out; a real URL
                    # never needs them unencoded, so one here is a mistake or a probe.
                    problems.append(f'{path}: link "{m.group(1)[:30]}" → "{url[:60]}" has a raw quote, '
                                    "angle bracket or backtick — percent-encode it")
        elif isinstance(v, dict):
            for k, x in v.items():
                if k != "svg":
                    walk(x, f"{path}.{k}")
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f"{path}[{i}]")
    walk(data or {})
    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("packet")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--register", choices=["eli5", "engineer"], default="engineer")
    a = ap.parse_args()

    html, data = load(a.packet)
    fail_problems, fail_warnings = check_failures(data, a.register)
    groups = [("context", check_context(html)), ("before/after", check_before_after(data)),
              ("components", check_components(data)),
              ("boundary review", check_boundary_review(html, data)),
              ("failure modes", fail_problems),
              ("links", check_links(data)), ("svg", check_svg(data))]
    if a.register == "eli5":
        groups.append(("register",
                       check_register(data, (data or {}).get("glossary", []))))

    total = sum(len(p) for _, p in groups)
    if fail_warnings:
        print(f"baton: {len(fail_warnings)} warning(s) — failure modes:", file=sys.stderr)
        for w in fail_warnings[:12]:
            print(f"    - {w}", file=sys.stderr)
        if len(fail_warnings) > 12:
            print(f"    … and {len(fail_warnings) - 12} more", file=sys.stderr)
    if not total:
        print("ok — context, components, before/after, boundary map, failure modes, runbook and register checked. "
              "Diagrams are checked in the browser (pipeline §6).")
        return 0

    print(f"baton: {total} problem(s)\n", file=sys.stderr)
    for name, problems in groups:
        if not problems:
            continue
        print(f"  {name}:", file=sys.stderr)
        for p in problems[:12]:
            print(f"    - {p}", file=sys.stderr)
        if len(problems) > 12:
            print(f"    … and {len(problems) - 12} more", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
