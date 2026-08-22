import { describe, expect, it } from "vitest";

import spendView from "./SpendView.vue?raw";
import costTrustPanel from "../components/CostTrustPanel.vue?raw";
import budgetHeadroom from "../components/BudgetHeadroom.vue?raw";

describe("SpendView data sources", () => {
  it("loads the rollup, the window before it, and the scrape on mount", () => {
    expect(spendView).toContain("api.spendWindow(activeWindow.value, groupBy.value)");
    expect(spendView).toContain("api.spendRange(range.from, range.to, groupBy.value)");
    expect(spendView).toContain("api.metrics()");
    expect(spendView).toContain("onMounted(");
    expect(spendView).toContain("void history.run()");
    expect(spendView).toContain("void prior.run()");
    expect(spendView).toContain("void metricsReq.run()");
  });

  it("recomputes the prior range at fetch time, not at mount", () => {
    // The window is rolling. A range captured once drifts away from "the
    // period before this one" for as long as the page stays open.
    expect(spendView).toMatch(
      /const prior = useAsync\(\(\) => \{\s*const range = priorWindowRange\(/,
    );
  });

  it("refetches both rollup calls when the window or dimension changes", () => {
    expect(spendView).toContain("watch([activeWindow, groupBy]");
  });

  it("renders errors and the empty state through the shared components", () => {
    expect(spendView).toMatch(/<ErrorState\s+v-else-if="history\.error\.value"/);
    expect(spendView).toContain('@retry="history.run"');
    expect(spendView).toMatch(
      /<EmptyState\s+v-else-if="!history\.loading\.value && !hasHistory"/,
    );
  });

  it("treats rollups being switched off as configuration, not failure", () => {
    expect(spendView).toContain("rollupsDisabled");
    expect(spendView).toContain("proxy.observability.usage_rollups");
  });
});

describe("SpendView above the fold", () => {
  it("names each tile for what it costs the person paying", () => {
    expect(spendView).toContain("`Spend, ${activeWindow}`");
    expect(spendView).toContain('label="Run rate"');
    expect(spendView).toContain('label="Unattributed"');
    expect(spendView).toContain('label="Per 1M tokens"');
  });

  it("gives the accent to one tile and no more", () => {
    expect(spendView.match(/tone="accent"/g)).toHaveLength(1);
  });

  it("calls the run rate a rate and never a forecast", () => {
    expect(spendView).toContain("if it holds");
    expect(spendView).not.toMatch(/forecast/i);
    expect(spendView).not.toMatch(/projected/i);
  });

  it("suppresses the unattributed tile when the grouping makes it meaningless", () => {
    // `group_by=total` writes an empty group for every row, so an
    // unattributed share there would read 100% and mean nothing.
    expect(spendView).toContain('groupBy.value !== "total"');
    expect(spendView).toContain("group by a dimension to see what it cannot name");
  });

  it("states price provenance and attribution coverage where the query is set", () => {
    expect(spendView).toContain("sbproxy_ai_price_source_total");
    expect(spendView).toContain("of price lookups used the shipped ");
    expect(spendView).toContain("fell back to the flat rate");
    expect(spendView).toContain("of spend in this window carries a ");
  });

  it("charts the two periods as a time series, with an axis that fits the fold", () => {
    // MiniBars is a ranked bar list and was never a time series. The
    // default clock tick would print "00:00:00" three times over a
    // thirty-day fold.
    expect(spendView).toContain("<LineChart");
    expect(spendView).toContain(':x-format="chartTick"');
    expect(spendView).toContain("var(--sb-chart-1)");
    expect(spendView).toContain("var(--sb-chart-2)");
  });

  it("says why a one hour window has no chart instead of drawing two dots", () => {
    expect(spendView).toContain("tooCoarseForChart");
    expect(spendView).toContain("Hourly is the finest rollup bucket");
  });
});

describe("SpendView breakdown", () => {
  it("carries share, delta, and unit cost per row", () => {
    expect(spendView).toContain("<th>Share</th>");
    expect(spendView).toContain("<th>vs prev</th>");
    expect(spendView).toContain("<th>$/1M tok</th>");
    expect(spendView).toContain("<th>Blocked</th>");
  });

  it("marks a group only one window saw rather than printing a zero delta", () => {
    expect(spendView).toContain("row.presence === 'new'");
    expect(spendView).toContain("row.presence === 'gone'");
  });

  it("keeps the folded tail's dollars so the bars sum to the headline", () => {
    expect(spendView).toContain("topNWithOther(rows.value, 8)");
  });

  it("leaves the bars unlinked and links the table rows instead", () => {
    // `linkFor` applies to every label in a MiniBars chart, and this one
    // carries an Other row and an unattributed row that nothing can
    // filter on.
    expect(spendView).not.toContain(":link-for");
    expect(spendView).toContain('RouterLink v-if="rowLink(row.group)"');
  });

  it("warns that the drill-down lands in a bounded ring", () => {
    expect(spendView).toContain("holds the last requests on this instance");
    expect(spendView).toContain("It is a recent sample, not the whole window.");
  });

  it("hands two-dimension work to the report that already does it", () => {
    expect(spendView).toContain("/reports?group_by=model,api_key_id");
  });
});

describe("SpendView savings panel", () => {
  it("reads every savings family by its exact name", () => {
    for (const family of [
      "sbproxy_ai_cost_saved_micros_total",
      "sbproxy_ai_tokens_saved_total",
      "sbproxy_semantic_cache_results_total",
      "sbproxy_ai_compression_value_cost_saved_micros_total",
      "sbproxy_ai_compression_value_tokens_saved_total",
      "sbproxy_ai_requests_attributed_total",
    ]) {
      expect(spendView).toContain(family);
    }
  });

  it("filters the token split and the refusal outcomes by their label values", () => {
    expect(spendView).toContain('{ kind: "prompt" }');
    expect(spendView).toContain('{ kind: "completion" }');
    expect(spendView).toContain('{ result: "hit" }');
    expect(spendView).toContain('"budget_exceeded"');
    expect(spendView).toContain('"price_ceiling_block"');
  });

  it("keeps the compression precision label visible beside the lever", () => {
    expect(spendView).toContain('"lever"');
    expect(spendView).toContain('"token_count_precision"');
  });

  it("states the basis, because these counters do not follow the window", () => {
    expect(spendView).toContain(
      "Savings counters are process-lifetime and are not in the durable rollup",
    );
  });

  it("branches on the family, never on the value being above zero", () => {
    // `sumSamples(undefined)` is 0, so a cache nobody enabled would
    // otherwise render an authoritative "$0.00 saved".
    expect(spendView).toContain('v-if="cacheSavedUsd !== undefined"');
    expect(spendView).toContain('v-if="compressionSavedUsd !== undefined"');
    expect(spendView).toContain("cacheSavedFamily.value !== undefined");
  });

  it("refuses to price the requests it refused", () => {
    // The count is measured; the avoided dollars are not accumulated
    // anywhere. Multiplying the count by an average price would print a
    // plausible number a customer could disprove.
    expect(spendView).toContain("The dollars these avoided are not measured.");
    expect(spendView).not.toMatch(/avoided[A-Za-z]*Usd|savedByBlock/);
  });

  it("never credits a savings total to a key", () => {
    // Neither cache-savings family carries `api_key_id`, so no per-key
    // savings figure is computable and none may be implied.
    expect(spendView).not.toMatch(
      /sbproxy_ai_cost_saved_micros_total[\s\S]{0,600}api_key_id/,
    );
    expect(spendView).not.toContain("saved by this key");
  });
});

describe("SpendView composition", () => {
  it("mounts the trust and budget panels with the one scrape it already has", () => {
    expect(spendView).toContain("<BudgetHeadroom");
    expect(spendView).toContain("<CostTrustPanel");
    expect(spendView).toContain(':families="families"');
  });

  it("only claims to know per-key spend when it grouped by key", () => {
    expect(spendView).toContain('if (groupBy.value !== "api_key") return undefined;');
  });

  it("writes no literal color", () => {
    expect(spendView).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
  });
});

describe("CostTrustPanel", () => {
  it("pins the four families it reads, two of which are alpha compat", () => {
    for (const family of [
      "sbproxy_ai_price_source_total",
      "sbproxy_ai_price_ceiling_total",
      "sbproxy_ai_token_estimate_error_ratio",
      "sbproxy_ai_cost_dollars_attributed_total",
    ]) {
      expect(costTrustPanel).toContain(family);
    }
  });

  it("says what the price-source counter cannot tell you", () => {
    expect(costTrustPanel).toContain("Counted per price lookup, not per request");
    expect(costTrustPanel).toMatch(/the family carries no\s+model label/);
    expect(costTrustPanel).toContain("$5 per million tokens in and $5 per million");
    // The direction of the error is the half an operator can act on.
    expect(costTrustPanel).toMatch(
      /rising fallback\s+share normally overstates spend/,
    );
  });

  it("distinguishes an absent price-source family from zero lookups", () => {
    expect(costTrustPanel).toContain('v-if="priceSources === undefined"');
    expect(costTrustPanel).toContain("is not reported by this build");
    expect(costTrustPanel).toContain('v-else-if="priceSources.total === 0"');
  });

  it("says the estimator runs unmeasured rather than drawing an empty chart", () => {
    expect(costTrustPanel).toMatch(
      /Estimator accuracy is only measured for models that have a per-model\s+rate limit configured\./,
    );
    expect(costTrustPanel).toMatch(
      /drives budget debits and the price ceiling is running unmeasured\./,
    );
  });

  it("names the gateway's own spend as not being caller traffic", () => {
    expect(costTrustPanel).toContain('surface: "compression_summary"');
    expect(costTrustPanel).toContain("not from caller traffic");
    expect(costTrustPanel).toContain("is not in the windowed history above");
  });

  it("links the refusal count at the requests that produced it", () => {
    expect(costTrustPanel).toContain('v-if="row.link && row.count > 0"');
  });

  it("writes no literal color", () => {
    expect(costTrustPanel).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
  });
});

describe("BudgetHeadroom", () => {
  it("reads the ledger per key and the gauge from the scrape", () => {
    expect(budgetHeadroom).toContain("api.keys()");
    expect(budgetHeadroom).toContain("api.keyUsage(row.id)");
    expect(budgetHeadroom).toContain("total_micro_usd");
    expect(budgetHeadroom).toContain("sbproxy_ai_budget_utilization_ratio");
  });

  it("bounds the fan-out and says what it left out", () => {
    expect(budgetHeadroom).toContain("const FAN_OUT_LIMIT = 20");
    expect(budgetHeadroom).toContain("capped keys");
    expect(budgetHeadroom).toContain("orderNote");
  });

  it("shows money held in reserve as its own segment", () => {
    expect(budgetHeadroom).toContain("held, of");
    expect(budgetHeadroom).toContain("cap__held");
  });

  it("says when the counter it read is degraded", () => {
    expect(budgetHeadroom).toContain("backend.status !== \"healthy\"");
    expect(budgetHeadroom).toMatch(
      /These balances may be behind\s+what the request path is enforcing\./,
    );
  });

  it("admits the scope gauge cannot name a workspace or a key", () => {
    expect(budgetHeadroom).toMatch(
      /This gauge carries no identity,\s+so it cannot say which workspace or which key\./,
    );
  });

  it("distinguishes an unconfigured gauge from every budget reading zero", () => {
    expect(budgetHeadroom).toContain('v-if="scopes === undefined"');
    expect(budgetHeadroom).toContain("Budget utilization is not reported.");
    expect(budgetHeadroom).toContain('v-else-if="!scopes.length"');
  });

  it("reuses the component that owns the workspace resume control", () => {
    expect(budgetHeadroom).toContain("<WorkspaceBudgets only-when-noteworthy />");
  });

  it("writes no literal color", () => {
    expect(budgetHeadroom).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
  });
});
