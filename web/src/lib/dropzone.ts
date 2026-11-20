/**
 * Drop zone: a container with a native `<input type="file">` inside.
 *
 * Keyboard and screen-reader users use the native input (Tab, then Enter or
 * Space opens the picker); the zone itself only adds drag-and-drop. While a
 * file is dragged over it the zone gets `data-dragover` (style hook). The
 * input is reset after each selection so choosing the same file again fires.
 *
 * With `multiple`, dropped folders are walked and their files delivered with
 * their path below the drop ({@link relativePath}); operating-system clutter
 * (`.DS_Store`, `Thumbs.db`, `desktop.ini`) inside folders is skipped.
 *
 * @module
 */

/** Paths of files that came from a dropped folder (`folder/sub/name`). */
const paths = new WeakMap<File, string>();

/** Path of a delivered file below what was dropped; its name if it was not in a folder. */
export function relativePath(file: File): string {
  return paths.get(file) ?? file.name;
}

/** Files a folder walk will collect at most, so a huge tree cannot freeze the page. */
export const MAX_DROPPED_FILES = 10_000;

/** A dropped folder holds more than {@link MAX_DROPPED_FILES} files. */
export class TooManyFilesError extends Error {
  override readonly name = "TooManyFilesError";
  readonly limit: number;
  constructor(limit: number) {
    super(`more than ${limit} files`);
    this.limit = limit;
  }
}

/** A dropped file or folder could not be read. */
export class DropReadError extends Error {
  override readonly name = "DropReadError";
  readonly path: string;
  constructor(path: string, options?: ErrorOptions) {
    super(`could not read ${path}`, options);
    this.path = path;
  }
}

const CLUTTER = new Set([".ds_store", "thumbs.db", "desktop.ini"]);

function readEntries(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  return new Promise((resolve, reject) => reader.readEntries(resolve, reject));
}

function entryFile(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => entry.file(resolve, reject));
}

async function walk(entry: FileSystemEntry, prefix: string, out: File[], limit: number): Promise<void> {
  const path = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
  if (entry.isFile) {
    if (prefix !== "" && CLUTTER.has(entry.name.toLowerCase())) return;
    if (out.length >= limit) throw new TooManyFilesError(limit);
    let file: File;
    try {
      file = await entryFile(entry as FileSystemFileEntry);
    } catch (cause) {
      throw new DropReadError(path, { cause });
    }
    if (prefix !== "") paths.set(file, path);
    out.push(file);
    return;
  }
  if (!entry.isDirectory) return;
  const reader = (entry as FileSystemDirectoryEntry).createReader();
  // readEntries returns batches (about 100 in Chrome) until an empty one.
  for (;;) {
    let batch: FileSystemEntry[];
    try {
      batch = await readEntries(reader);
    } catch (cause) {
      throw new DropReadError(path, { cause });
    }
    if (batch.length === 0) return;
    for (const child of batch) await walk(child, path, out, limit);
  }
}

/**
 * The files of a drop, folders walked. Entries must be taken synchronously
 * in the drop handler: the DataTransfer is emptied once it returns.
 */
function droppedEntries(dt: DataTransfer): FileSystemEntry[] | null {
  const entries: FileSystemEntry[] = [];
  let folder = false;
  for (const item of Array.from(dt.items)) {
    if (item.kind !== "file") continue;
    const entry = typeof item.webkitGetAsEntry === "function" ? item.webkitGetAsEntry() : null;
    if (entry === null) return null; // no entry API: fall back to dt.files
    if (entry.isDirectory) folder = true;
    entries.push(entry);
  }
  return folder ? entries : null;
}

export interface DropZoneOptions {
  /** Accept several files per drop, and folders (default: the input's `multiple`). */
  readonly multiple?: boolean;
  /** Called instead of `onFiles` when a dropped folder cannot be collected. */
  readonly onError?: (e: unknown) => void;
  /** Called when a dropped folder starts being read (it may take a moment). */
  readonly onCollecting?: () => void;
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
    if (!enabled || ev.dataTransfer === null) return;
    const entries = multiple ? droppedEntries(ev.dataTransfer) : null;
    if (entries === null) {
      deliver(ev.dataTransfer.files);
      return;
    }
    opts.onCollecting?.();
    void (async () => {
      const files: File[] = [];
      try {
        for (const entry of entries) await walk(entry, "", files, MAX_DROPPED_FILES);
      } catch (e) {
        if (opts.onError) opts.onError(e);
        else console.error(e);
        return;
      }
      if (enabled && files.length > 0) onFiles(files);
      else if (files.length === 0) opts.onError?.(new DropReadError(entries.map((e) => e.name).join(", ")));
    })();
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
