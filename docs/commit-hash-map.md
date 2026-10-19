# Commit hash map

On 2026-10-19 the repository history was rewritten once, to remove a
co-author line from the commit messages. Only the messages changed: every
commit's files, author, committer, dates and subject are identical, and
each new commit has exactly the same file tree as the old one.

Every commit hash changed. Documents and evidence written before the
rewrite still cite the **old** hashes, among them:
- `CLAUDE.md`, `ENGINEERING_CHANGELOG.md`, `docs/`, `docs/team-onboarding/`;
- `results/acceptance/*/README.md`;
- recorded run manifests.

Recorded evidence is deliberately left unchanged. Use this table to
translate an old hash into the commit that exists now.

| Old hash | New hash | Branch | Subject |
|---|---|---|---|
| `795c945` | `a1be2b9` | master | chore: initial baseline commit of M0 snapshot collector and PPT requirements |
| `67af42d` | `b67abc2` | master | docs: establish master CLAUDE.md architecture and ML contracts |
| `3df5819` | `1256d0d` | master | feat: complete M1 telemetry foundations and acceptance tests |
| `d9b9e9b` | `610702a` | master | feat(m1b): implement S0 telemetry v2 framing, validation, and snapshot protocol |
| `391c988` | `4346fab` | master | refactor(m1b): implement S1 unified bpf compilation and per-thread lifecycle tracking |
| `5f0d376` | `d1ff507` | master | feat(m1b): implement S2.1-S2.4 bounded syscall bigram storage and map accounting |
| `1f763de` | `615896d` | master | fix(m1b): synchronize in-flight BPF readers before purge |
| `d1d7eac` | `ecbe7d2` | master | feat(m1b): implement S2.5 final-drain protocol and double-read map accounting |
| `699c2c8` | `5a45db3` | master | feat(m1b): implement S2.6 agent integration and schema v2 bigram emitter |
| `9a628a3` | `cc546ab` | master | docs: add team onboarding package, collaboration protocol and S3 network plan |
| `3a2451e` | `5b6231b` | wip/s3.2-network | wip(m1b): S3.1/S3.2 network capability (connect/accept) - NOT ACCEPTED |

The old commits are **not** on GitHub. Only the project owner's machine
keeps them, under the local tags `backup/pre-rewrite-master` and
`backup/pre-rewrite-wip`. The pairs were verified there to have identical
trees, authors, committers, dates, subjects and parents.
