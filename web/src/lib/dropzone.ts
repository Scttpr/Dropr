/**
 * Drop zone: a container with a native `<input type="file">` inside.
 *
 * Keyboard and screen-reader users use the native input (Tab, then Enter or
 * Space opens the picker); the zone itself only adds drag-and-drop. While a
 * file is dragged over it the zone gets `data-dragover` (style hook). The
 * input is reset after each selection so choosing the same file again fires.
 *
 * @module
 */

export interface DropZoneOptions {
  /** Accept several files per drop (default: the input's `multiple`). */
  readonly multiple?: boolean;
}

export interface DropZone {
  /** Enable/disable both the input and dropping (e.g. while uploading). */
  setEnabled(enabled: boolean): void;
}

export function attachDropZone(
  zone: HTMLElement,
  input: HTMLInputElement,
  onFiles: (files: File[]) => void,
  opts: DropZoneOptions = {},
): DropZone {
  const multiple = opts.multiple ?? input.multiple;
  let enabled = true;
  let depth = 0;

  const deliver = (list: FileList | null): void => {
    if (!enabled || list === null || list.length === 0) return;
    const files = Array.from(list);
    onFiles(multiple ? files : files.slice(0, 1));
  };

  input.addEventListener("change", () => {
    deliver(input.files);
    input.value = "";
  });

  const hasFiles = (ev: DragEvent): boolean => ev.dataTransfer !== null && Array.from(ev.dataTransfer.types).includes("Files");

  zone.addEventListener("dragenter", (ev) => {
    if (!hasFiles(ev)) return;
    ev.preventDefault();
    depth++;
    if (enabled) zone.dataset["dragover"] = "";
  });
  zone.addEventListener("dragover", (ev) => {
    if (!hasFiles(ev)) return;
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = enabled ? "copy" : "none";
  });
  zone.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    if (depth === 0) delete zone.dataset["dragover"];
  });
  zone.addEventListener("drop", (ev) => {
    if (!hasFiles(ev)) return;
    ev.preventDefault();
    depth = 0;
    delete zone.dataset["dragover"];
    deliver(ev.dataTransfer?.files ?? null);
  });
  // A file dropped next to the zone must not navigate away from the page.
  for (const type of ["dragover", "drop"] as const) {
    window.addEventListener(type, (ev) => {
      if (ev.dataTransfer !== null && Array.from(ev.dataTransfer.types).includes("Files")) ev.preventDefault();
    });
  }

  return {
    setEnabled(v: boolean) {
      enabled = v;
      input.disabled = !v;
      zone.toggleAttribute("aria-disabled", !v);
      if (!v) zone.setAttribute("aria-disabled", "true");
    },
  };
}
