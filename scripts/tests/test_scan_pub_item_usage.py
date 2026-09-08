#!/usr/bin/env python3
"""Behavior tests for the public-item usage scanner."""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "scripts" / "scan-pub-item-usage.py"


def _scanner_module():
    """Import the scanner for direct calls, despite the hyphens in its name."""
    spec = importlib.util.spec_from_file_location("scan_pub_item_usage", SCANNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PubItemUsageScannerTest(unittest.TestCase):
    def test_example_only_consumer_stays_in_the_tests_only_bucket(self) -> None:
        """An example binary is a demo, not a shipping library consumer."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            source = repo / "crates" / "fixture" / "src"
            examples = repo / "crates" / "fixture" / "examples"
            source.mkdir(parents=True)
            examples.mkdir(parents=True)
            (source / "lib.rs").write_text("pub fn example_only() {}\n")
            (examples / "demo.rs").write_text(
                "use fixture::example_only;\nfn main() { example_only(); }\n"
            )

            completed = subprocess.run(
                [
                    "python3",
                    str(SCANNER),
                    "--repo",
                    str(repo),
                    "--count",
                    "tests-only",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.stdout.strip(), "1")


class CfgTestLineRangeTest(unittest.TestCase):
    """The brace counting `cfg_test_line_ranges` does, in both directions.

    This function decides which references count as production, so the
    direction it fails in decides whether the ratchet over-counts usage
    or under-counts it. Its docstring used to call any miscount
    conservative. Half of that was wrong, and nothing here caught it: a
    test fixture that matched on the byte string `data: {` extended a
    range in `ai_dispatch.rs` by roughly 5,000 lines, swallowed the only
    production reference to `sbproxy_ai::model_group::routing_name`, and
    reddened the ratchet while pointing at the wrong crate. These pin
    the asymmetry so the docstring is defended by something that runs.

    None of this is the real fix. Counting braces without lexing Rust
    cannot be made correct, and the remedy is to strip string and char
    literals before counting. That changes what the scanner reports
    across the whole tree, so it belongs in its own change with its own
    baseline re-derivation rather than here.
    """

    def test_an_unbalanced_opening_brace_runs_the_range_past_the_block(self) -> None:
        """The unsafe direction: the range swallows production code."""
        module = _scanner_module()
        lines = [
            "#[cfg(test)]\n",
            "mod tests {\n",
            '    const OPENER: &[u8] = b"data: {";\n',
            "}\n",
            "pub fn production_reference_below_the_block() {}\n",
        ]

        ranges = module.cfg_test_line_ranges(lines)

        self.assertEqual(ranges, [(1, 5)])
        covered = [
            line
            for number, line in enumerate(lines, start=1)
            if any(first <= number <= last for first, last in ranges)
        ]
        self.assertIn(
            "pub fn production_reference_below_the_block() {}\n",
            covered,
            "the stray `{` has to pull the production line into the test range, "
            "because that is what files a live reference as a test consumer and "
            "drives the tests-only count up",
        )

    def test_an_unbalanced_closing_brace_ends_the_range_early(self) -> None:
        """The safe direction: the range closes before the block does."""
        module = _scanner_module()
        lines = [
            "#[cfg(test)]\n",
            "mod tests {\n",
            '    const CLOSER: &str = "}";\n',
            "    fn genuinely_inside_the_block() {}\n",
            "}\n",
        ]

        ranges = module.cfg_test_line_ranges(lines)

        self.assertEqual(ranges, [(1, 3)])
        covered = [
            line
            for number, line in enumerate(lines, start=1)
            if any(first <= number <= last for first, last in ranges)
        ]
        self.assertNotIn(
            "    fn genuinely_inside_the_block() {}\n",
            covered,
            "the stray `}` has to close the range early, leaving test code read as "
            "production, which makes an item look more used rather than less",
        )

    def test_a_block_with_no_literal_braces_covers_exactly_itself(self) -> None:
        """The control, so the two above are about the literals."""
        module = _scanner_module()
        lines = [
            "pub fn before() {}\n",
            "#[cfg(test)]\n",
            "mod tests {\n",
            "    fn inside() {}\n",
            "}\n",
            "pub fn after() {}\n",
        ]

        self.assertEqual(module.cfg_test_line_ranges(lines), [(2, 5)])


class DeriveAttributionTest(unittest.TestCase):
    """Which derives a definition is recorded with.

    The serde/schemars rule is the only thing standing between a
    deserialized type and a `wire-or-delete` verdict, because the caller
    that builds one is a YAML document or a Kubernetes API server rather
    than any Rust reference the scan can find. So the derive list has to
    survive whatever sits between `#[derive(...)]` and the item.
    """

    def test_a_multi_line_attribute_does_not_erase_the_derives(self) -> None:
        """The shape in crates/sbproxy-k8s-controller/src/gateway_api.rs.

        `#[derive(.., Deserialize, .., JsonSchema)]`, then a seven-line
        `#[kube(...)]`, then the struct. The continuation lines of that
        attribute are not blank, not comments, and do not start with
        `#`, so they used to be read as ordinary code and clear the
        pending derives. All four CRD spec structs in that file lost
        their `Deserialize`, missed the keep rule, and were triaged as
        having no consumer at all.
        """
        module = _scanner_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            source = repo / "crates" / "fixture" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(
                "#[derive(Debug, Clone, Deserialize, JsonSchema)]\n"
                "#[kube(\n"
                '    group = "gateway.networking.k8s.io",\n'
                '    version = "v1",\n'
                ")]\n"
                '#[serde(rename_all = "camelCase")]\n'
                "pub struct GatewaySpec {\n"
                "    pub field: String,\n"
                "}\n"
            )

            definitions = module.collect_definitions(
                module.rust_files(repo / "crates"), repo
            )

        self.assertIn("GatewaySpec", definitions)
        self.assertIn("Deserialize", definitions["GatewaySpec"][0]["derives"])
        self.assertEqual(
            module.verdict_for(definitions["GatewaySpec"][0])[0],
            "keep",
            "a deserialized type has a caller no reference search can see",
        )

    def test_an_unbalanced_paren_inside_a_string_does_not_open_an_attribute(self) -> None:
        """`#[serde(rename = "a(b")]` is balanced Rust and unbalanced text.

        Reading it as unbalanced would keep the accumulator open over
        every line that follows, dropping the rest of the file's items
        from the scan, which moves the count DOWN and is the direction
        that hides work rather than inventing it.
        """
        module = _scanner_module()
        self.assertTrue(module.attribute_is_closed('#[serde(rename = "a(b")]'))
        self.assertFalse(module.attribute_is_closed("#[kube("))


class RunawayAttributeTest(unittest.TestCase):
    """An attribute the balance test cannot close must not eat definitions.

    This is the accumulator's dangerous direction. Losing derives gives an
    item the wrong verdict; losing the item removes it from the inventory
    and both counts at once, with the floor unmoved because the rest of
    the tree still discovers plenty. A guard cannot refuse what it cannot
    see, so the accumulator has to let go at a definition.
    """

    def _definitions(self, source: str):
        module = _scanner_module()
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            src = repo / "crates" / "fixture" / "src"
            src.mkdir(parents=True)
            (src / "lib.rs").write_text(source)
            return module.collect_definitions(module.rust_files(repo / "crates"), repo)

    def test_a_char_literal_delimiter_does_not_swallow_the_items_below_it(self) -> None:
        """`attribute_is_closed` blanks string literals, not char literals,
        so the `(` in `'('` never balances and the accumulator runs on.

        Measured before the fix: all three of these left the scan, and
        `--count definitions` went to zero for the file while the two
        ratchet counts and the inventory stayed exactly where they were.
        """
        definitions = self._definitions(
            "#[foo(sep = '(')]\n"
            "pub struct Swallowed {\n"
            "    pub field: String,\n"
            "}\n"
            "pub fn also_swallowed() {}\n"
            "pub fn survivor() {}\n"
        )
        for name in ("Swallowed", "also_swallowed", "survivor"):
            self.assertIn(name, definitions, f"{name} left the scanner's universe")

    def test_a_comment_carrying_a_lone_paren_does_not_swallow_them_either(self) -> None:
        """The same hole reached through a comment rather than a literal."""
        definitions = self._definitions(
            "#[serde(\n"
            "    // the opening ( here is prose\n"
            "    default\n"
            ")]\n"
            "pub struct StillSeen {}\n"
        )
        self.assertIn("StillSeen", definitions)

    def test_derives_recorded_before_a_runaway_attribute_survive(self) -> None:
        """Letting go at the item must not undo the fix that added the
        accumulator: the derives from before it are still the item's."""
        definitions = self._definitions(
            "#[derive(Debug, Deserialize)]\n"
            "#[foo(sep = '(')]\n"
            "pub struct Kept {}\n"
        )
        self.assertIn("Kept", definitions)
        self.assertIn("Deserialize", definitions["Kept"][0]["derives"])


class ReExportIsNotAConsumerTest(unittest.TestCase):
    """A `pub use` names an item; it does not consume one.

    `collect_definitions` already skips those lines for exactly this
    reason. `collect_references` counted them as production references,
    so a module wired to nothing but its own crate's facade read as
    used and never entered either ratchet bucket (WOR-2550).
    """

    def _count(self, lib_rs: str, module_rs: str) -> str:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            source = repo / "crates" / "fixture" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text(lib_rs)
            (source / "inner.rs").write_text(module_rs)
            completed = subprocess.run(
                ["python3", str(SCANNER), "--repo", str(repo), "--count", "unreferenced"],
                check=True,
                capture_output=True,
                text=True,
            )
        return completed.stdout.strip()

    def test_a_facade_re_export_alone_leaves_the_item_a_candidate(self) -> None:
        self.assertEqual(
            self._count(
                "pub mod inner;\npub use inner::facade_only;\n",
                "pub fn facade_only() {}\n",
            ),
            "1",
        )

    def test_a_re_export_wrapped_across_lines_is_skipped_whole(self) -> None:
        """rustfmt wraps a wide `pub use`, so only its first line matches.

        Skipping just that line left the continuation lines counting as
        production references, which is most of the real ones: the
        facade lines that hid items in this workspace were mostly
        wrapped `pub use x::{A, B, C};` blocks.
        """
        self.assertEqual(
            self._count(
                "pub mod inner;\npub use inner::{\n    facade_only,\n    other,\n};\n",
                "pub fn facade_only() {}\npub fn other() {}\n",
            ),
            "2",
        )

    def test_a_real_caller_still_counts(self) -> None:
        """The control. Without it the two above pass on a scanner that
        counts nothing at all as a reference."""
        self.assertEqual(
            self._count(
                "pub mod inner;\nfn caller() { inner::facade_only(); }\n",
                "pub fn facade_only() {}\n",
            ),
            "0",
        )


class PublicApiCrateTest(unittest.TestCase):
    """The five crates CLAUDE.md names as the public API surface.

    Every `pub` item in one of them is published API whatever this scan
    can see about its callers, so the two verdicts that change a
    signature are both wrong there.
    """

    def _verdict(self, crate: str) -> tuple[str, str]:
        module = _scanner_module()
        return module.verdict_for(
            {
                "name": "thing",
                "kind": "fn",
                "crate": crate,
                "file": f"crates/{crate}/src/lib.rs",
                "used_in_own_file": 3,
                "derives": [],
            }
        )

    def test_a_public_api_crate_item_is_never_narrowed(self) -> None:
        """`pub(crate)` on a published crate's item is a breaking change,
        and in-file use was making this scan advise exactly that."""
        for crate in (
            "sbproxy-plugin",
            "sbproxy-config",
            "sbproxy-httpkit",
            "sb-runtime-core",
            "sb-runtime-host",
        ):
            with self.subTest(crate=crate):
                verdict, why = self._verdict(crate)
                self.assertEqual(verdict, "keep")
                self.assertIn("public API surface", why)

    def test_an_internal_crate_with_the_same_shape_still_narrows(self) -> None:
        """The control. Without it the test above passes on a scanner
        that returns `keep` for everything."""
        self.assertEqual(self._verdict("sbproxy-mesh")[0], "narrow")

    def test_the_planned_crates_are_not_treated_as_shipped(self) -> None:
        """CLAUDE.md names sbproxy-events and sbproxy-proxy as planned and
        not yet shipped, and says not to advertise them as available."""
        module = _scanner_module()
        self.assertNotIn("sbproxy-events", module.PUBLIC_API_CRATES)
        self.assertNotIn("sbproxy-proxy", module.PUBLIC_API_CRATES)


class DiscoveryFloorTest(unittest.TestCase):
    """A scan that found nothing has to say so.

    Every number this scanner prints is "how many of the things I found
    look unused", so an empty discovery reports zero of everything and a
    ratchet reading it sees the best result the repository has ever had.
    """

    def test_an_empty_tree_is_an_error_rather_than_a_clean_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "crates").mkdir()
            completed = subprocess.run(
                ["python3", str(SCANNER), "--repo", str(repo), "--count", "unreferenced"],
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 2, completed.stdout)
        self.assertEqual(completed.stdout.strip(), "", "a broken run must not print a count")
        self.assertIn("broken run, not a clean tree", completed.stderr)

    def test_a_tree_with_no_pub_items_is_also_an_error(self) -> None:
        """Files found, nothing matched. The regex breaking looks like
        this, and it is not a clean tree either."""
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            source = repo / "crates" / "fixture" / "src"
            source.mkdir(parents=True)
            (source / "lib.rs").write_text("fn private_only() {}\n")
            completed = subprocess.run(
                ["python3", str(SCANNER), "--repo", str(repo), "--count", "unreferenced"],
                capture_output=True,
                text=True,
            )

        self.assertEqual(completed.returncode, 2, completed.stdout)
        self.assertIn("broken run, not a clean tree", completed.stderr)


if __name__ == "__main__":
    unittest.main()
