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
             "guard", "summary", "ref"}


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("packet")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--register", choices=["eli5", "engineer"], default="engineer")
    a = ap.parse_args()

    html, data = load(a.packet)
    groups = [("context", check_context(html))]
    if a.register == "eli5":
        groups.append(("register",
                       check_register(data, (data or {}).get("glossary", []))))

    total = sum(len(p) for _, p in groups)
    if not total:
        print("ok — context and register checked. "
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
