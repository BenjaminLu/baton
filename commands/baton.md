---
description: "One entry point for baton — routes to baton:brief, baton:review, or baton:handoff by reading the input, never by asking"
---

Route this request to exactly one baton skill, then invoke that skill with the
same arguments and follow it. Decide from the evidence below — do NOT ask the
user to pick an entry point; the whole point of /baton is that routing is your
job. Ask only when the input is a genuine stub (a title and a few bullets) —
and then the question is about the missing content, not about which skill.

ARGUMENTS: $ARGUMENTS

## Routing rules, in order

1. **The input is a document about work not yet done** — a PRD, spec, RFC,
   design proposal, decision doc, requirements file, 需求文档/设计文档/決策文件,
   whether pasted inline, attached, or named by path/URL → `baton:brief`.
   Tell-tales: user stories, acceptance criteria, options under consideration,
   "we should/will build", no commits or session work corresponding to it yet.

2. **The work already happened and the reader reads code** — summarize this
   session/branch/commits/bugfix/investigation, "pack this up", "review where
   we are", "I'm stopping here", 總結這幾個 commit, future-me or a colleague
   engineer inheriting the branch → `baton:review`.

3. **The work already happened and the reader does NOT read code** — "for my
   PM", "report upward", "explain to the boss", 向上報告, executive/director/
   non-technical audience named or implied → `baton:handoff`.

## Tie-breakers

- Done work with no audience stated → `baton:review` (engineer register is
  the safe default; handoff requires an explicitly non-technical reader).
- A document that describes work which the repo/session shows is ALREADY
  implemented is not a proposal anymore: treat it as done work (rule 2/3) and
  say so on the page — brief's proposal framing would mislead.
- Mixed input (a spec plus a session that partially implemented it) → route
  by the deliverable the user asked for: "visualise/align on the plan" →
  brief; "where did we get to" → review/handoff.

After routing, announce in one short line which skill you chose and why
(e.g. "已路由到 baton:review — 這是已完成的 commit 總結，讀者是工程師"),
then execute that skill in full.
