export interface SpendGroupOption {
  value: string;
  label: string;
  unavailable: boolean;
}

const BUILT_IN_GROUPS: readonly Omit<SpendGroupOption, "unavailable">[] = [
  { value: "total", label: "Total" },
  { value: "model", label: "Model" },
  { value: "provider", label: "Provider" },
  { value: "team", label: "Team" },
  { value: "project", label: "Project" },
  { value: "api_key", label: "API key" },
  { value: "origin", label: "Origin" },
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
