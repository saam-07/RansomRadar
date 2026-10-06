# PROJECT RULES

- Defensive security project only. Ransomware behavior is simulated with numbers and virtual files, or with the existing safe simulator confined to a throwaway sandbox directory. Never write real encryption code that touches real user files.
- Reuse the existing `adaptshield` package. Import it; do not duplicate detection logic.
- Do only the task in the current prompt. Do not start the next one.
- Start every task with a short plan (files to touch, order, risks), then implement.
- Never claim something works unless you ran it. End every task with: (a) what changed, (b) exact commands you ran and their results, (c) what you could NOT verify and how I can verify it.
- Do not fake metrics, screenshots or results. Every number shown must be computed from real data or models in the repo.
- Synthetic data must always be labeled synthetic (in files, API responses and UI). Synthetic-trained accuracy is never presented as real-world performance.
- Keep docs/PROGRESS.md updated: done / verified / not verified / next.
- Small, reviewable commits with conventional commit messages. Work on a branch named for the task. Do not push to main.
- If something is ambiguous, pick a sensible default, state it, and continue. Ask only if a wrong guess is costly to undo.
