---
name: review
description: Compact the current working session into one self-contained HTML packet so any coding agent can resume the work later. Use when the user says "baton", "review this", "review where we are", "pack this up", "I'm stopping here", "hand this to future me", "save context before I switch", or wants to see and hand on the state of work they will return to days or weeks later — a feature branch, a debugging session, a refactor, a performance hunt, a dependency upgrade, a local experiment with no branch at all. This packages work already done in this session for an engineer; use `baton:handoff` when the reader is a product manager or executive, and `baton:brief` when the input is a document about work not yet done.
---

# baton:review

Stop work without losing the state in your head. One HTML file: a short walk
through where things stand, with the **complete context** embedded — the
record, the compaction of this session, how to pull more (pipeline §2) — so
the reader's agent continues as if it had just run `/compact`, and can fetch
anything the compaction left out.

Same pipeline as `baton:handoff` (`references/pipeline.md`); the differences:

## The reader

You, weeks later — or a colleague inheriting the branch. An engineer who has
forgotten, not one who was never told. Register is **engineer**: identifiers,
paths and code stay.

## What matters most

The compaction's *paths taken and abandoned*. A diff shows the approach that
survived; only the session knows the three that were tried and reverted and
why they died — the ruled-out auth gateway, the rejected storage approach,
the state removed on product grounds and the unverified assumption that
removal rests on. That is what a closing session throws away, and recovering
it is why this skill exists.

## Order of work

1. Ground truth — pipeline §1: the session first, then git, the pull request
   and the design docs *if they exist*. A debugging afternoon with no branch
   packs just as well as a merged feature; never refuse for want of a repo.
2. Context, all three layers — pipeline §2. For a past session you were not
   part of, read the transcript JSONL under `~/.claude/projects/<slug>/`
   selectively — the user turns and the failed commands, filtered with a
   short inline command, not the whole stream; the deliverable is still all
   three layers.
3. Page via `render.py` (baton's template; spec shape in
   `references/spec.md`), lean: where this got to, **the change itself** —
   for a bugfix or fix series, one `vuln` card **per fix**, each with its own
   before/after severed-chain diagram, the fix's `file:line` in `ref`, and
   the mechanism named in the fix text (`diagrams.md` § Per-fix before/after;
   generate the SVGs from one layout function, never free-draw a set). The
   same per-item rule holds beyond fixes: an ask to explain each commit,
   each workstream, or each migration step gets one small figure per item
   (pipeline §3), prose demoted to captions. A
   status page that never shows what was actually fixed reads as if nothing
   was — this shipped once, and a text-only list was rejected next: the
   reader wanted to *see* where each chain breaks. Then the diagrams — from a
   design doc if the repo has one, otherwise drawn from
   the code and labelled as inferred; never skipped — roads not taken, next
   steps. Skip `eli5` unless
   the wording needs sharpening — the audience is an engineer.
4. `verify.py --register engineer`, then the real-browser check, pipeline §6
   — non-skippable. Publish with `Artifact` if a URL is wanted; otherwise
   the file beside the work is the deliverable.

## When not to run

No transcript and no session context — then there is nothing to compact, and
`git log` in costume is worse than saying so.
