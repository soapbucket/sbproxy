# Change fragments

One file per user-visible change. The release cut assembles them into
[`CHANGELOG.md`](../../CHANGELOG.md) and deletes them.

## Why this directory exists

Every branch that appends to a shared `## [Unreleased]` heading edits the
same few lines, so every branch open at the same time conflicts there.
On 2026-08-20 five pull requests each needed a hand-resolution on that
one file and on nothing else. Two branches writing two files here do not
conflict at all.

## Adding one

```bash
python3 scripts/changelog-fragments.py --new fixed \
  'A `failure_posture: closed` transform now fails the request instead of passing it through.'
```

That writes `docs/.changes/<YYYYMMDD>-<slug>.json` and prints the path.
Edit the file afterwards if the message needs more than one sentence;
the tool only saves you the filename and the JSON quoting.

## When a fragment is required

Required when a reader of the release notes would change what they do:

- new configuration keys, routes, metrics, or CLI flags
- behavior that differs from the previous release, including defaults
- a bug fix somebody could have hit
- anything with a security consequence
- anything removed or deprecated

Not required for changes no operator can observe: refactors, test-only
work, CI and gate changes, comment and internal-documentation edits,
dependency bumps with no behavior change. When in doubt, write one. A
release cut can drop a fragment it decides is noise, and cannot recover
one nobody wrote.

## The file

```json
{
  "type": "fixed",
  "message": "`ldap_auth` and its `ldap` alias validate clean."
}
```

`type` is one of, and assembles under a heading in this order:

| `type` | Heading |
|---|---|
| `breaking` | `### Breaking` |
| `security` | `### Security` |
| `added` | `### Added` |
| `changed` | `### Changed` |
| `deprecated` | `### Deprecated` |
| `removed` | `### Removed` |
| `fixed` | `### Fixed` |

`message` is the body of one CHANGELOG bullet, in Markdown, without the
leading `- `. House style opens with a bold sentence naming the change
and follows it with what an operator has to do about it. Line breaks
inside a paragraph do not matter: assembly re-wraps every message to the
same width, so a message written as one long line and one carrying the
line breaks it had in the CHANGELOG render identically. Blank lines
separate paragraphs and are kept.

No other keys. An unexpected key is refused rather than ignored, because
a key nobody reads is a fact nobody publishes.

## Filename

`YYYYMMDD-slug.json`. The date is the day the fragment was written and
the slug is lowercase words joined by hyphens. Both exist so that two
branches never pick the same name, which is the whole point of the
directory.

## Releasing

```bash
python3 scripts/changelog-fragments.py --preview            # what it will say
python3 scripts/changelog-fragments.py --release 1.14.0     # write it
```

`--release` replaces the `## [Unreleased]` placeholder with a
`## [1.14.0] - <today>` section carrying the assembled fragments, then
deletes the fragments it consumed. Already released sections are never
read or rewritten. Pass `--date` for a cut dated other than today.

The heading text in an assembled section is a normal part of the release
commit: past releases have used flavored headings such as
`### Changed, and worth checking before you upgrade`, and a cut is free
to rename one. The fragment carries the type, not the prose.

## The gate

`python3 scripts/changelog-fragments.py --check` runs on every pull
request and in `scripts/check.sh`. It refuses a malformed fragment, any
hand-written content under `## [Unreleased]`, and a commit that edits
`CHANGELOG.md` without touching this directory in the same diff. A
release cut passes without a flag, because assembling deletes fragments
and so touches both.
