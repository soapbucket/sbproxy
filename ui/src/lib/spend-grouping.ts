export interface SpendGroupOption {
  value: string;
  label: string;
  unavailable: boolean;
}

/**
 * Every dimension `GroupBy::parse` accepts, in the order an operator
 * narrows: the whole bill, then what it bought, then who bought it.
 *
 * `tenant` and `agent` were missing here while the server answered both,
 * so "which agent spent this" was queryable by hand-editing the URL and
 * not from the page.
 */
const BUILT_IN_GROUPS: readonly Omit<SpendGroupOption, "unavailable">[] = [
  { value: "total", label: "Total" },
  { value: "model", label: "Model" },
  { value: "provider", label: "Provider" },
  { value: "tenant", label: "Tenant" },
  { value: "team", label: "Team" },
  { value: "project", label: "Project" },
  { value: "api_key", label: "API key" },
  { value: "origin", label: "Origin" },
  { value: "agent", label: "Agent" },
];

export function spendGroupOptions(
  propertyKeys: readonly string[],
  selected: string,
): SpendGroupOption[] {
  const available = [...new Set(propertyKeys.filter((key) => key.length > 0))].sort();
  const options: SpendGroupOption[] = [
    ...BUILT_IN_GROUPS.map((option) => ({ ...option, unavailable: false })),
    ...available.map((key) => ({
      value: `property:${key}`,
      label: `Property: ${key}`,
      unavailable: false,
    })),
  ];

  if (selected.startsWith("property:")) {
    const key = selected.slice("property:".length);
    if (key && !available.includes(key)) {
      options.push({
        value: selected,
        label: `Property: ${key} (unavailable in window)`,
        unavailable: true,
      });
    }
  }
  return options;
}
