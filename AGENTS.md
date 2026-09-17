# baton — for any coding agent

baton turns the work in your context window into one self-contained HTML page: a
few diagrams a non-engineer reads in minutes, with the **complete session
context** embedded so the reader's own coding agent — Claude Code, Codex,
Cursor, anything — can load it and keep going.

This file is the entry point for agents that read `AGENTS.md` (Codex and
others). Claude Code users get the same thing as the personal skill `/baton`
(this directory symlinked into `~/.claude/skills/baton`). Either way the
method is identical and lives in one place.

## One job, two decisions — what you are packaging and who reads it

`SKILL.md` decides both from the evidence, never by asking:

**What is the input?**
- **Work done in this session** — packaged as what happened.
- **A document** — PRD, spec, RFC, decision record — about work **not yet
  done**, rendered as what is proposed.

**Who reads the page?**
- **An engineer who has forgotten** — future you, or whoever inherits the
  branch. Register `engineer`.
- **A product manager or executive who will not open the repo.** Register
  `eli5`. For a document, the register follows the document's own audience.

**A git repo is not required.** The session is the floor — a debugging
afternoon, a local experiment, an investigation with no commits all pack. Git,
a pull request and design docs are enhancements you add when you find them.

The split that matters: **done work is packaged as what happened; a document
is rendered as what is proposed.** A proposal must say *proposal* on its face
— a reader who mistakes an intended flow for a shipped one plans against
something that does not exist.

## The method
`references/pipeline.md` is the full build. Read it, then
`SKILL.md` for what differs by route. Diagram vocabulary is in
`references/diagrams.md`; extraction rules in `references/extraction.md`.

## You do the work; two scripts do the assembly
Extraction is yours, with your own tools and judgment: `gh pr view` and
`gh pr diff` for the pull-request record, `git merge-base HEAD origin/<base>`
for the change boundary, `find` and reading for the design docs and
migrations, your own context window (or the transcript JSONL under
`~/.claude/projects/<slug>/`) for the session history, and the
`diagram-design` skill for the diagrams — you supply the structure from the
design docs you read, it draws, and you embed the extracted inline SVG under
the contract in `references/diagrams.md`. No script stands between you and
any of that —
`references/pipeline.md` walks the whole build.

Only three scripts exist, all mechanical on purpose. They live in `scripts/`
next to this file and **locate their own siblings** (template, assets) via
their file path, so they run from any working directory:

```bash
BATON=/path/to/baton          # this directory (Claude Code: ${CLAUDE_SKILL_DIR})
python3 "$BATON/scripts/render.py"   .baton/packet.json -o baton-<slug>.html
python3 "$BATON/scripts/verify.py"   baton-<slug>.html --register <eli5|engineer>
python3 "$BATON/scripts/snapshot.py" baton-<slug>.html -o <scratch-dir>
```

`render.py` assembles the page — fills the template and escapes the
payloads; an agent cannot emit that by hand. `verify.py` scans for the absences a
reading agent is bad at noticing: a missing refusal declaration, a context
short enough to be a digest, an identifier left bare in prose meant for a
non-engineer. `snapshot.py` renders the page headless, fails on the mechanical
diagram defects (a missing language attribute, a label overflowing its box,
CJK below 12px, a blank step) and emits the screenshots; correctness is then
checked by eye on those screenshots or in a live browser. The packet spec's
exact shape is `references/spec.md` — never reverse-engineered from the
template.

Requirements: Python 3 (standard library only), `git`, and `gh` for pull-request
context (degrades gracefully without it). Diagrams are static inline SVG
drawn by the `diagram-design` skill — no runtime diagram library in the page,
no network, no CDN.

## The one rule that matters most
The embedded context is the complete compaction of the session in three layers
— what already happened, your own summary, and the commands to pull more — not a
thin digest. A page whose context could be regenerated from `git log` has
failed. Everything else is in `references/pipeline.md`.
