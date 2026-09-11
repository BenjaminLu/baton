---
name: brief
description: Turn a PRD, spec, design doc or cross-team decision document into one HTML page whose diagrams make the proposal legible — user journey, decisions taken and rejected, scope in and out, risks, open questions — with the full document embedded for any coding agent. Use when the user pastes or points at a requirements document, product spec, RFC, technical proposal, 需求文档, 设计文档 or 决策文件 and wants it visualised, explained, or turned into something a team can align on. This reads a document about work not yet done; use `baton:review` or `baton:handoff` instead when packaging work already carried out in a session.
---

# baton:brief

A document arrives — a PRD, a spec, an RFC, a cross-team decision. Turn it into
one page whose diagrams carry the argument, with the document itself embedded
so the reader's coding agent can go deeper.

Follow `references/pipeline.md` for the build. This file is what differs for a
document that describes work **not yet done**.

## The one rule this entry point lives or dies by

**A proposal is not behaviour.** The reader cannot tell your diagram of an
intended flow from a diagram of a shipped one, and if they confuse the two
they will plan against something that does not exist. So:

- The subtitle, the footer and the context's first line all say **proposal**
- `layer` is `proposal`, never `L0`/`L1`
- Where implementation *does* exist, say which parts — and say what is
  inferred where it does not

## Always diagrams

A document rendered as prose is the thing this format replaces. If the
document carries diagrams, reuse their structure; if it does not, draw from
what it describes and say the drawing is your reading of it. The one thing
never to ship is no diagram at all.

## First: read the document and decide what it is

The kind decides the diagrams. Read it, then pick:

| what you find | the shape it wants |
|---|---|
| user stories, acceptance criteria, flows | the **user journey** as a flowchart; the fiddliest acceptance rule as a **decision tree** |
| a decision with rejected alternatives | **rejected vs recommended**, side by side — the alternatives are the argument |
| several competing options weighed against each other | the full **comparison treatment** (`diagrams.md`): a decision matrix on the separating questions, one mechanism drawing per option, and paired what-it-buys / what-it-costs panels |
| a risk register | the top risks as **attack paths**, entry → impact, with the control that cuts each |
| scope and non-goals | **in / out** panels; a non-goal is a decision, not an omission |
| API or data contracts | a **sequence** for the exchange, a **state machine** if it has a lifecycle |
| open questions | a list at the end, ranked by what blocks the most work |

Most documents want three or four of these, not all. A section whose source
paragraph is thin should not become a diagram.

## Then: check it against the code

Detect whether the repo already implements any of this — search for the
feature's nouns, look for the routes and modules it names. Two outcomes, both
worth saying plainly:

- **Nothing exists yet.** Every diagram is the proposal. Say so once, clearly.
- **Some of it exists.** Mark which parts have code behind them and which do
  not, and flag anywhere the document contradicts what the code already does —
  that contradiction is the most valuable thing on the page, and only this
  entry point can find it.

## The context

Three layers as always (pipeline §2), with (a) different: for a document, the
record is **the document itself, carried whole**. Do not summarise it into the
packet — the diagrams are the summary; the context is the source. Then your
own reading of it (what it decides, what it leaves open, what it contradicts),
then how to pull more: the specs it cites, the code that would implement it.

## Register

Whoever the document is for. A PRD read by a PM takes `--register eli5`; an
RFC among engineers takes `engineer`. Keep the mechanism's proper nouns either
way — a decision about EIP-712 is not a decision about "signing".

## When not to run

The document is a stub — a title and a few bullets. Say so; a page of diagrams
drawn from three sentences invents structure the author never committed to.
