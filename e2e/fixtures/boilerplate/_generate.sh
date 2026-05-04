#!/usr/bin/env bash
# Regenerate the 50 boilerplate fixtures.
#
# This script is committed alongside the fixtures so that when the
# next maintainer wants to grow the suite to 60 they can read what
# the current pattern is and extend, instead of reverse-engineering
# from the .html files alone. The committed .html and
# .expected.txt files in this directory are the source of truth for
# the test suite; this script is documentation by way of executable
# code.
#
# Run from the repo root:
#     bash e2e/fixtures/boilerplate/_generate.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

archetypes=(
  "news-article"
  "news-article"
  "news-article"
  "news-article"
  "news-article"
  "blog-post"
  "blog-post"
  "blog-post"
  "blog-post"
  "blog-post"
  "product-page"
  "product-page"
  "product-page"
  "product-page"
  "product-page"
  "documentation"
  "documentation"
  "documentation"
  "documentation"
  "documentation"
  "long-form-essay"
  "long-form-essay"
  "long-form-essay"
  "long-form-essay"
  "long-form-essay"
  "api-reference"
  "api-reference"
  "api-reference"
  "api-reference"
  "api-reference"
  "forum-thread"
  "forum-thread"
  "forum-thread"
  "forum-thread"
  "forum-thread"
  "marketing-landing"
  "marketing-landing"
  "marketing-landing"
  "marketing-landing"
  "marketing-landing"
  "recipe"
  "recipe"
  "recipe"
  "recipe"
  "recipe"
  "encyclopedia"
  "encyclopedia"
  "encyclopedia"
  "encyclopedia"
  "encyclopedia"
)

main_paragraphs() {
  case "$1" in
    news-article)
      cat <<'P'
The city council voted on Tuesday to expand the downtown bike-lane network by twelve miles over the next two years.
The proposal had been stalled since the spring after several business owners raised concerns about delivery access.
A revised plan adds dedicated loading windows on streets where new lanes will be installed.
P
      ;;
    blog-post)
      cat <<'P'
Last weekend I rebuilt my home network from scratch and learned three things worth writing down.
First, the cheapest managed switch is fine for a five-device home; the bottleneck is always the upstream link.
Second, putting the router in the basement was the worst decision; signal degradation is wall-by-wall, not foot-by-foot.
P
      ;;
    product-page)
      cat <<'P'
The Foundry-7 desk lamp uses a single warm-white LED panel with a continuous-dimming driver.
At full brightness it draws nine watts and outputs roughly 800 lumens, comparable to a 60-watt incandescent.
The included weighted base accommodates a workspace clamp via a hex insert on the underside.
P
      ;;
    documentation)
      cat <<'P'
The configure() function accepts a builder and returns a Handle bound to the runtime that called it.
A Handle is cheap to clone and safe to send across threads; the underlying state is reference-counted.
Calling configure() twice on the same builder panics; the builder is moved on the first call.
P
      ;;
    long-form-essay)
      cat <<'P'
The notion of the public sphere has narrowed in step with the platforms that host it.
What was once a network of front pages and letter columns is now a cluster of recommendation engines.
The shift is not a moral failure; it is the predictable end-state of optimizing for click-through.
P
      ;;
    api-reference)
      cat <<'P'
GET /v1/widgets/{id} returns a single Widget resource keyed by its server-assigned identifier.
The response is wrapped in an envelope with a top-level data field and a meta block carrying request_id.
A 404 is returned when no widget exists for the supplied id; the body is the standard error envelope.
P
      ;;
    forum-thread)
      cat <<'P'
I have been running the same Postgres replica for three years and the WAL replay lag finally caught up to me.
Bumping max_wal_senders did nothing; the bottleneck was the receiving side's fsync cadence.
The fix was switching the replica's filesystem from ext4 with default mount options to ext4 with data=writeback.
P
      ;;
    marketing-landing)
      cat <<'P'
Foundry helps small teams ship API contracts faster by generating typed clients from OpenAPI in real time.
Drop a spec into the Foundry CLI and the toolchain emits Go, TypeScript, and Python clients in seconds.
Each generated client carries a stable version pin so downstream services can adopt the new contract on their own schedule.
P
      ;;
    recipe)
      cat <<'P'
This skillet cornbread relies on the contrast between a heavily preheated cast-iron pan and a cool batter.
The preheat caramelizes the butter against the pan, building a crust before the interior begins to set.
Pull the bread when the center reads 195 F on an instant-read thermometer; a few minutes past that and the crumb dries out.
P
      ;;
    encyclopedia)
      cat <<'P'
The Snell's window is the optical phenomenon by which an underwater observer sees the entire above-water hemisphere compressed into a roughly 97-degree cone.
The compression follows from Snell's law of refraction at the air-water interface; light arriving from grazing angles is bent inward by the index difference.
Outside the cone, the surface acts as a near-perfect mirror, reflecting the underwater scene back at the observer.
P
      ;;
  esac
}

boilerplate_block() {
  local archetype="$1"
  local idx="$2"
  cat <<HTML
<nav class="site-nav">
  <a href="/">Home STRIP-ME-BOILERPLATE</a>
  <a href="/about">About STRIP-ME-BOILERPLATE</a>
  <a href="/contact">Contact STRIP-ME-BOILERPLATE</a>
</nav>
<aside class="sidebar">
  <h3>Trending STRIP-ME-BOILERPLATE</h3>
  <ul>
    <li>Sponsored link STRIP-ME-BOILERPLATE</li>
    <li>Related listicle STRIP-ME-BOILERPLATE</li>
    <li>Newsletter signup STRIP-ME-BOILERPLATE</li>
  </ul>
</aside>
<footer class="site-footer">
  <p>(c) 2026 Example Corp STRIP-ME-BOILERPLATE</p>
  <p>Privacy STRIP-ME-BOILERPLATE | Terms STRIP-ME-BOILERPLATE | Cookies STRIP-ME-BOILERPLATE</p>
</footer>
HTML
}

for i in $(seq 1 50); do
  idx=$(printf '%02d' "$i")
  arch="${archetypes[$((i-1))]}"
  html_path="fixture-${idx}.html"
  expected_path="fixture-${idx}.expected.txt"

  paragraphs="$(main_paragraphs "$arch")"
  printf '%s\n' "$paragraphs" > "$expected_path"

  {
    printf '<!doctype html>\n'
    printf '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    printf '<title>%s fixture %s</title>\n' "$arch" "$idx"
    printf '<!-- archetype: %s; index: %s -->\n' "$arch" "$idx"
    printf '</head>\n<body>\n'
    boilerplate_block "$arch" "$i"
    printf '<article class="main-content">\n'
    printf '<h1>%s fixture %s</h1>\n' "$arch" "$idx"
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      printf '  <p>%s</p>\n' "$line"
    done <<< "$paragraphs"
    printf '</article>\n'
    printf '</body>\n</html>\n'
  } > "$html_path"
done

echo "Generated 50 fixture pairs."
