# baton

**Pass the baton.** Turn the work sitting in your coding agent's context into
one self-contained HTML page — a few diagrams a non-engineer reads in minutes,
with the *complete session context* embedded so the reader's own coding agent
can load it and keep going.

AI made every engineer's output explode, but the bandwidth between people did
not grow. baton is the handoff: not a summary someone re-derives, but the real
working history — every path tried and dropped, every review round, the schema
writes behind each state — packaged so a person skims it and their agent
resumes from it.

## One skill: `/baton`

| packages | reads like |
|---|---|
| this session's work | an engineer who has forgotten |
| this session's work | a PM or exec asking "what can now go wrong for our users?" |
| a PRD, spec or decision doc | a team aligning on work not yet done — marked *proposal*, never mistaken for shipped |

`/baton` decides which row from what you ask — the input and the reader —
and never asks you to pick. Any coding work qualifies — a merged feature, a debugging session, a
refactor, an incident, a local experiment with no branch. A repo helps; it is
not required. Every route produces the same kind of page: an outline you walk, diagrams drawn by
the `diagram-design` skill from the repo's own design docs and embedded as
static inline SVG (architecture, an interactive state
machine linked to the database write behind each state, sequence, the DB
lifecycle as transactions, before/after, attack-path for a security fix), a
three-language switch (EN / 繁 / 简), and a one-click **copy the context to
your AI**. It works offline and inside a sandboxed iframe.

## Install

**Claude Code** — clone it and link it in as a personal skill; the command is
`/baton`:
```
git clone https://github.com/BenjaminLu/baton ~/.claude/baton
ln -s ~/.claude/baton ~/.claude/skills/baton
```
To update later: `git -C ~/.claude/baton pull`. Skills load at session
start, so open a new session after installing.

**Codex, Cursor, and other agents** — clone the repo and point your agent at
`AGENTS.md`; it carries the same workflow and script paths.

## Try it in two minutes — on a Pokémon dilemma

No repo, no setup, and the data is fetched live. Ask `/baton` to settle
gaming's most famous irreversible decision:

```
claude "/baton Which Eevee evolution should I commit to? Fetch the real
stats from PokeAPI, embed the sprites, and lay it out as a decision"
```

What comes out is one HTML file that treats the question with the same rigour
as a security audit — which is the joke, and also the point. All eight
evolutions share the *same six base stats, permuted*, so the page becomes a
matrix of where each one puts its 130, a quadrant of who plays which role
(sprites included), and an acquisition-cost map (buy a stone / grind
friendship / walk to one specific rock in Sinnoh) — with the fetch commands
embedded so the reader's own agent can verify every number.

## Or on something your PM would recognise — PEP 703

Point it at the famous "remove the GIL" proposal and ask for a page a
product manager could read:

```
claude "/baton https://peps.python.org/pep-0703/ — make the free-threaded
Python decision legible to someone who has never heard of the GIL"
```

What comes out is one HTML file: the rejected alternatives drawn next to what
was accepted, the conditions attached to acceptance, the open questions ranked
by what they block — and the **entire PEP embedded** behind a copy button, so
whoever you send it to can paste the full context into their own Claude Code /
Codex / Cursor and interrogate the proposal past what the page shows.

Any RFC, PEP, KEP, TC39 proposal or design doc works the same way — they are
all decision documents, which `/baton` recognises as a proposal. Done work
needs no URL at all: after any real coding session, just say **"baton"** to
pack it for an engineer, or **"write this up for my PM"** to pack it for
someone who doesn't read code.

## Requirements
Python 3 (standard library only), `git`, and `gh` for pull-request context
(optional — degrades gracefully). Diagrams are static inline SVG drawn by the
`diagram-design` skill — no runtime diagram library, no network at view time.

## How it's built
`references/pipeline.md` is the whole method; `references/diagrams.md` the
diagram vocabulary; `templates/packet.html` the page. The agent does the
extraction itself — `gh` for the pull request, `git merge-base` for the
boundary, reading for the design docs and migrations, its own session for the
history — and invokes the `diagram-design` skill to draw, embedding the
extracted SVG. `scripts/` holds the only two scripts: `render.py`, which
assembles the packet spec into the single HTML file (filling the template and
escaping the payloads), and `verify.py`, which scans for
mechanical absences (the context's refusal declaration, a digest-thin
context, the register). Diagram correctness is checked by eye in a real
browser — that is the gate.

MIT.
