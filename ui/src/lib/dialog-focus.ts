export function focusTargetForTab<T>(
  focusable: readonly T[],
  active: T | null,
  backwards: boolean,
): T | null {
  if (focusable.length === 0) return null;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  const activeIndex = active === null ? -1 : focusable.indexOf(active);
  if (activeIndex === -1) return backwards ? last : first;
  if (backwards && activeIndex === 0) return last;
  if (!backwards && activeIndex === focusable.length - 1) return first;
  return null;
}
