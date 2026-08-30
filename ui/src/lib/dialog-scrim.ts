/** Scrim dismiss that ignores a text-selection drag ending on the backdrop. */

export function createScrimDismiss(onClose: () => void): {
  onScrimMouseDown: (event: MouseEvent) => void;
  onScrimClick: (event: MouseEvent) => void;
} {
  let downOnScrim = false;
  return {
    onScrimMouseDown(event: MouseEvent) {
      downOnScrim = event.target === event.currentTarget;
    },
    onScrimClick(event: MouseEvent) {
      if (downOnScrim && event.target === event.currentTarget) {
        onClose();
      }
      downOnScrim = false;
    },
  };
}
