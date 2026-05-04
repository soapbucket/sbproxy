# Boilerplate-stripping fixtures (Q4.9)

*Last modified: 2026-05-01*

50 synthesized HTML pages exercising the common shapes a boilerplate
stripper must handle in production. None of these are scraped from
real sites; they are hand-written so the test suite is reproducible
and free of third-party content.

## Layout

Each fixture is two files:

- `fixture-NN.html`     - the input HTML page.
- `fixture-NN.expected.txt` - the canonical "main content" text the
  stripper should preserve (one paragraph per line). Used by
  `boilerplate_strip_preserves_main_content` and
  `boilerplate_strip_quality_threshold`.

## Shape catalog

The 50 fixtures cover ten archetypes, five variations each:

| Range | Archetype | Boilerplate it carries |
|---|---|---|
| 01-05 | News article | `<nav>`, `<aside>` sidebar, `<footer>` |
| 06-10 | Blog post | `<header>` author bio, comment section, share buttons |
| 11-15 | Product page | `<nav>`, related-items panel, reviews carousel |
| 16-20 | Documentation page | left-rail TOC, right-rail "on this page", footer |
| 21-25 | Long-form essay | site nav, tag cloud, related-reading footer |
| 26-30 | API reference | left-rail symbol index, footer link grid |
| 31-35 | Forum thread | nav, sidebar widgets, "trending" panel |
| 36-40 | Marketing landing page | hero nav, footer columns, cookie banner |
| 41-45 | Recipe page | recipe metadata header, comment section, ad slots |
| 46-50 | Encyclopedic article | hatnote, infobox, references, "see also" footer |

The archetype hint is the comment block at the top of each
`.html` file.

## Boilerplate markers

Every fixture's boilerplate region contains the literal sentinel
`STRIP-ME-BOILERPLATE` so the test can assert that none of those
sentinels survive into the stripped output. The expected text never
contains the sentinel.

## Adding a fixture

1. Pick the next free slot (`fixture-51.html`).
2. Wrap the main content in `<article class="main-content">`. The
   reference stripper uses that selector; adding a fixture under a
   different selector is fine but document it in the comment block.
3. Sprinkle `STRIP-ME-BOILERPLATE` in every nav, sidebar, footer,
   and ad block.
4. Copy the visible main content into `fixture-51.expected.txt`,
   one paragraph per line.

## License

Synthesized text. Public domain.
