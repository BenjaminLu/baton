---
name: handoff
description: Compact the current working session into one beautiful HTML page a product manager or executive reads in minutes, with the complete working history embedded for their own coding agent. Use when the user says "baton handoff", "write this up for my PM", "report this upward", "explain this to the boss", "向上报告", or needs to hand engineering work — a feature, an incident, an investigation, a migration, a security fix — to someone who does not read code. This packages work already done in this session; use `baton:brief` when the input is a requirements or decision document about work not yet done.
---

# baton:handoff

You did a piece of work. This skill turns it into one page: diagrams a
non-engineer walks through in minutes, with the **complete compaction of your
session** embedded so their own coding agent — Claude Code, Codex, Cursor,
anything — can pick up where you are and keep answering.

It is an orchestration skill: `eli5` for the audience, baton's own
template for the page, the repo's design documents for the diagrams when it
has them and your reading of the code when it does not, the
origin pull request for ground truth, `Artifact` for the URL. It adds one thing —
the embedded context, three layers deep (pipeline §2). Follow
`references/pipeline.md` for the build; this file is only what differs for
this reader.

## The reader

A product manager or an executive. Not stupid, not lazy — no context, very
little time, and one question: **what can now go wrong for our users?**
Change is your unit; risk is theirs.

## Order of work

1. **Ground truth** — pipeline §1: the session first, then git, the pull
   request, the design docs and the migrations *if they exist* — each an
   enhancement, none a prerequisite. An investigation or an incident with no
   commits still has a record worth reporting upward.
2. **Context** — pipeline §2, all three layers: the record, your complete
   compaction — you lived it; write every workstream — and the fetch
   instructions. This is the packet; build it before the page, which is only
   a view of it.
3. **Wording** — invoke `eli5`, audience Product Manager (Director for an
   executive). Hand it your compaction and the extracted facts.
4. **Page** — `render.py` fills baton's template (scroll / one-pager) —
   the mechanical assembly step, the one place a script does the work.
   Typical sections, each dropped if its source is empty:
   - *What this is* — one paragraph a person could repeat
   - *What talks to what* — the design doc's architecture diagram, adapted
   - *The order's life* — the state machine, each transition openable to its
     one database transaction — full set, never a subset (`diagrams.md`)
   - *One payment, in order* — the design doc's sequence diagram, real loops
     and fallbacks kept, labels reworded
   - *What to watch* — risks only, each traceable; an empty list is a
     finding, an invented one is a lie
5. **Verify** — `verify.py --register eli5`; fix by finding a real word,
   never by deleting the sentence. Then the real-browser check, pipeline §6
   — non-skippable; a packet once shipped on script checks alone was
   completely broken.
6. **Publish** — `Artifact`, hand back the URL.

## Do not guess

The reader cannot tell your inferences from your facts, so do not mix them.
Deployment state — whether a migration ran, whether users see anything today
— is not in the repository. When there is no PR, or `gh` cannot reach the
forge, say nothing about tests or reviews. "Not recorded here — ask" is a
complete answer; a guess spends trust you cannot get back.

## When not to run

Say so plainly instead of shipping a hollow packet: when the session did no
substantive work (nothing to compact but metadata), or when the change has
no reader-facing consequence at all.
