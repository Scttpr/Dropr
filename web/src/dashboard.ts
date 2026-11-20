/**
 * Dashboard (`/`): share files (flow A: one file as is, several as one ZIP
 * archive built in the browser, lib/zip.ts) and create a request link (flow B)
 * whose key pair is generated and kept in this browser (lib/request-keys.ts).
 * DOM contract: docs/PAGES.md §Dashboard.
 *
 * @module
 */

import {
  b64urlEncode,
  ciphertextSize,
  deriveFileKeys,
  encodeRequestFragment,
  encodeShareFragment,
  generateFileKey,
  generateRequestKeyPair,
  partCount,
  sealMeta,
} from "./crypto/index.ts";
import { type ExpiresIn, api, isExpiry } from "./lib/api.ts";
import { Notice, byId, dataInt, el, maybeId, pageRoot, revealJsOnly, warnBeforeUnload } from "./lib/dom.ts";
import { DropReadError, MAX_DROPPED_FILES, TooManyFilesError, attachDropZone, relativePath } from "./lib/dropzone.ts";
import { expiryChoiceText, formatBytes, formatInteger } from "./lib/format.ts";
import { t } from "./lib/i18n.ts";
import { showLink } from "./lib/linkview.ts";
import { KeyIdTakenError, requestKeysFor, requestPersistence } from "./lib/request-keys.ts";
import { RateMeter } from "./lib/progress.ts";
import { isAbortError } from "./lib/retry.ts";
import { ProgressPanel, runUploadWithPanel } from "./lib/transfer-ui.ts";
import { Uploader } from "./lib/uploader.ts";
import { FileReadError, type PickedFile, type ZipInput, buildZip, safeEntryName, withChecksums, zipInputs } from "./lib/zip.ts";

function expiryFrom(select: HTMLSelectElement | null, fallback: ExpiresIn): ExpiresIn {
  const v = select?.value;
  return isExpiry(v) ? v : fallback;
}

/** `data-default-expiry` if valid, else "" (the server's default, DESIGN.md §6). */
function defaultExpiryOf(main: HTMLElement): ExpiresIn {
  const d = main.dataset["defaultExpiry"];
  return isExpiry(d) ? d : "";
}

/** The `max` attribute of input (the instance cap), else fallback. */
function inputMax(input: HTMLInputElement | null, fallback: number): number {
  const m = input?.max ?? "";
  return /^\d{1,6}$/.test(m) && Number(m) >= 1 ? Number(m) : fallback;
}

/** The whole number in input, undefined if empty, null if not in 1..max. */
function optionalPositiveInt(input: HTMLInputElement | null, max: number): number | undefined | null {
  const raw = input?.value.trim() ?? "";
  if (raw === "") return undefined;
  if (!/^\d{1,6}$/.test(raw) || Number(raw) < 1 || Number(raw) > max) return null; // invalid
  return Number(raw);
}

/** Local calendar date as `YYYY-MM-DD`. */
function isoDate(d: Date): string {
  const pad = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** What one share link carries: the file itself, or a ZIP archive of several. */
interface Payload {
  readonly name: string;
  readonly type: string;
  /** Plaintext size, exact (for an archive, the archive's). */
  readonly size: number;
  /** Members of the archive, unchecksummed; null for a single file. */
  readonly members: ZipInput[] | null;
  readonly single: File | null;
}

/** Same file picked twice (same path, size and modification time). */
function pickKey(p: PickedFile): string {
  return `${p.path}\u0000${p.file.size}\u0000${p.file.lastModified}`;
}

function payloadOf(picked: readonly PickedFile[]): Payload {
  const first = picked[0];
  if (picked.length === 1 && first !== undefined) {
    return { name: first.file.name, type: first.file.type, size: first.file.size, members: null, single: first.file };
  }
  // One dropped folder: name the archive after it.
  const tops = new Set(picked.map((p) => (p.path.includes("/") ? p.path.slice(0, p.path.indexOf("/")) : "")));
  const [top] = tops;
  const name = tops.size === 1 && top !== undefined && top !== "" ? `${safeEntryName(top)}.zip` : t.archiveName(isoDate(new Date()));
  const members = zipInputs(picked);
  return { name, type: "application/zip", size: buildZip(members).size, members, single: null };
}

function errorText(e: unknown): unknown {
  if (e instanceof FileReadError) return t.fileUnreadable(e.entry);
  if (e instanceof DropReadError) return t.dropUnreadable(e.path);
  if (e instanceof TooManyFilesError) return t.tooManyFiles(formatInteger(e.limit));
  return e;
}

function initShare(main: HTMLElement): void {
  const maxSize = dataInt(main, "maxFileSize", 5_000_000_000);
  const defaultExpiry = defaultExpiryOf(main);
  const form = byId("share-form", HTMLFormElement);
  const input = byId("file-input", HTMLInputElement);
  const expirySel = maybeId("expires-in", HTMLSelectElement);
  const maxDl = maybeId("max-downloads", HTMLInputElement);
  const notice = new Notice(byId("share-error"));
  const selection = maybeId("share-selection");
  const list = maybeId("share-files", HTMLUListElement);
  const summary = maybeId("share-summary");
  const live = maybeId("share-selection-status");
  const submit = maybeId("share-submit", HTMLButtonElement);
  const clear = maybeId("share-clear", HTMLButtonElement);
  const panel = new ProgressPanel({
    panel: "upload-panel",
    name: "upload-file-name",
    progress: "upload-progress",
    status: "upload-status",
    cancel: "upload-cancel",
    retry: "upload-retry",
  });
  const result = byId("share-result");
  let picked: PickedFile[] = [];
  let busy = false;
  warnBeforeUnload(() => busy);

  const tooLargeText = (pl: Payload): string => {
    const limit = formatBytes(maxSize);
    // Just over the limit both round to the same figure; show the exact size instead.
    const have = formatBytes(pl.size) === limit ? t.exactBytes(formatInteger(pl.size)) : formatBytes(pl.size);
    return pl.members !== null ? t.selectionTooLarge(have, limit) : t.fileTooLarge(have, limit);
  };

  const announce = (text: string): void => {
    if (live === null) return;
    // Clear first so the same sentence twice is announced twice.
    live.textContent = "";
    requestAnimationFrame(() => (live.textContent = text));
  };

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void share();
  });

  const zone = attachDropZone(
    byId("drop-zone"),
    input,
    (files) => {
      if (submit === null) {
        // Markup without a selection list (PAGES.md minimum): share right away.
        picked = files.slice(0, 1).map((file) => ({ file, path: file.name }));
        void share();
        return;
      }
      add(files.map((file) => ({ file, path: relativePath(file) })));
    },
    {
      multiple: submit !== null && input.multiple,
      onCollecting: () => announce(t.readingFolder),
      onError: (e) => notice.error(errorText(e)),
    },
  );

  function add(files: readonly PickedFile[]): void {
    notice.clear();
    const seen = new Set(picked.map(pickKey));
    const fresh = files.filter((f) => {
      const k = pickKey(f);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    if (picked.length + fresh.length > MAX_DROPPED_FILES) {
      notice.error(t.tooManyFiles(formatInteger(MAX_DROPPED_FILES)));
      return;
    }
    picked = picked.concat(fresh);
    const problem = render();
    announce(t.filesAdded(fresh.length, picked.length, files.length - fresh.length) + (problem !== null ? ` ${problem}` : ""));
  }

  function removeAt(i: number, name: string): void {
    if (picked[i] === undefined) return;
    picked = picked.filter((_, j) => j !== i);
    notice.clear();
    render();
    announce(picked.length === 0 ? t.listCleared : t.fileRemoved(name, picked.length));
    // Keep the keyboard where it was: the next row, else the previous one, else the picker.
    const buttons = list?.querySelectorAll("button") ?? [];
    const next = buttons[Math.min(i, buttons.length - 1)];
    (next instanceof HTMLButtonElement ? next : input).focus();
  }

  /** Redraw the selection; returns the over-limit message, if any. */
  function render(): string | null {
    if (list === null || selection === null) return null;
    // Show each file under the name it will have in the archive (made safe
    // and unique), so two "notes.txt" from different folders are told apart.
    const names = picked.length > 1 ? zipInputs(picked).map((m) => m.name) : picked.map((p) => p.file.name);
    const rows = picked.map((p, i) => {
      const name = names[i] ?? p.path;
      const btn = el("button", {
        class: "button button-quiet file-row-remove",
        text: t.remove,
        attrs: { type: "button", "aria-label": t.removeNamed(name) },
      });
      btn.addEventListener("click", () => removeAt(i, name));
      return el(
        "li",
        { class: "file-row" },
        el("span", { class: "file-row-name", text: name }),
        el("span", { class: "file-row-size", text: formatBytes(p.file.size) }),
        btn,
      );
    });
    list.replaceChildren(...rows);
    selection.hidden = picked.length === 0;
    if (clear) clear.hidden = picked.length < 2;
    if (submit) submit.textContent = t.shareSubmit(picked.length);
    if (picked.length === 0) {
      if (summary !== null) summary.textContent = "";
      return null;
    }
    const pl = payloadOf(picked);
    const problem = pl.size > maxSize ? tooLargeText(pl) : null;
    if (summary !== null) {
      summary.classList.toggle("over", problem !== null);
      summary.textContent =
        problem ??
        t.selectionSummary(picked.length, formatBytes(pl.size), formatBytes(maxSize)) +
          (pl.members !== null ? " " + t.selectionArchive(pl.name) : "");
    }
    return problem;
  }

  clear?.addEventListener("click", () => {
    picked = [];
    notice.clear();
    render();
    announce(t.listCleared);
    input.focus();
  });

  maybeId("share-another", HTMLButtonElement)?.addEventListener("click", () => {
    result.hidden = true;
    panel.hide();
    form.hidden = false;
    input.focus();
  });

  /** Read every member once for its CRC-32, with progress and Cancel on the panel. */
  async function checksum(members: readonly ZipInput[], name: string): Promise<ZipInput[]> {
    panel.start(name, t.preparing);
    const ctl = new AbortController();
    const onCancel = (): void => ctl.abort();
    panel.cancelBtn?.addEventListener("click", onCancel);
    const meter = new RateMeter(
      members.reduce((s, m) => s + m.data.size, 0),
      performance.now(),
    );
    try {
      return await withChecksums(members, {
        signal: ctl.signal,
        onProgress: (done) => panel.update(meter.update(done, performance.now()), t.preparing),
      });
    } finally {
      panel.cancelBtn?.removeEventListener("click", onCancel);
    }
  }

  async function share(): Promise<void> {
    if (busy) return;
    notice.clear();
    if (picked.length === 0) {
      notice.error(t.noFileChosen, false);
      input.focus();
      return;
    }
    const pl = payloadOf(picked);
    if (pl.size > maxSize) {
      notice.error(tooLargeText(pl));
      return;
    }
    const downloadCap = inputMax(maxDl, 999_999);
    const maxDownloads = optionalPositiveInt(maxDl, downloadCap);
    if (maxDownloads === null) {
      notice.error(t.downloadLimitInvalid(formatInteger(downloadCap)));
      maxDl?.focus();
      return;
    }
    const expiresIn = expiryFrom(expirySel, defaultExpiry);
    busy = true;
    zone.setEnabled(false);
    result.hidden = true;
    form.hidden = true;
    let shareId: string | null = null;
    let finished = false;
    try {
      // The archive is built before any request: nothing reaches the server
      // until every file has been read once.
      const data: Blob = pl.single ?? buildZip(await checksum(pl.members ?? [], pl.name));
      const fk = generateFileKey();
      const keys = await deriveFileKeys(fk);
      const meta = await sealMeta(keys.metadata, { name: pl.name, type: pl.type, size: data.size });
      const size = ciphertextSize(data.size);
      const created = await api.createShare({
        size,
        parts: partCount(size),
        meta: b64urlEncode(meta),
        expires_in: expiresIn,
        ...(maxDownloads !== undefined ? { max_downloads: maxDownloads } : {}),
      });
      shareId = created.share_id;
      const uploader = new Uploader({
        file: data,
        contentKey: keys.content,
        uploadId: created.upload_id,
        uploadToken: created.upload_token,
        onProgress: (p) => panel.update(p, t.uploading),
      });
      await runUploadWithPanel(uploader, panel, pl.name);
      finished = true;
      const url = `${location.origin}/s/${created.share_id}#${encodeShareFragment(fk)}`;
      fk.fill(0);
      panel.finish(t.uploadReady);
      bumpCount("link-count");
      picked = [];
      render();
      showLink(
        { container: "share-result", input: "share-link", copy: "share-copy", expiry: "share-expiry" },
        url,
        expiryChoiceText(expiresIn),
      );
    } catch (e) {
      panel.hide();
      form.hidden = false;
      // The selection is kept, so the user can fix it and try again.
      if (!isAbortError(e)) notice.error(errorText(e));
      // Do not leave an unusable share behind.
      if (shareId !== null && !finished) void api.deleteShare(shareId).catch(() => undefined);
    } finally {
      busy = false;
      zone.setEnabled(true);
    }
  }
}

/** Add one to a dashboard tile count (`<span id="link-count">`), if shown. */
function bumpCount(id: string): void {
  const el = maybeId(id);
  if (el === null) return;
  const n = Number.parseInt(el.textContent ?? "", 10);
  if (Number.isSafeInteger(n) && n >= 0) el.textContent = String(n + 1);
}

function initRequest(main: HTMLElement): void {
  const form = maybeId("request-form", HTMLFormElement);
  if (form === null) return;
  const notice = new Notice(byId("request-error"), maybeId("request-status"));
  const submit = maybeId("request-create", HTMLButtonElement);
  const defaultExpiry = defaultExpiryOf(main);
  const maxBytes = dataInt(main, "maxRequestBytes", dataInt(main, "maxFileSize", 5_000_000_000));
  const requestKeys = requestKeysFor(main);

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void create();
  });

  async function create(): Promise<void> {
    notice.clear();
    if (requestKeys.ownerId === null) {
      // Fail closed: without the account, the key could not be filed under it.
      notice.error(t.ownerUnknown);
      return;
    }
    const singleUse = maybeId("request-single-use", HTMLInputElement)?.checked ?? false;
    const maxFilesInput = maybeId("request-max-files", HTMLInputElement);
    const filesCap = inputMax(maxFilesInput, 1000);
    const parsed = singleUse ? 1 : optionalPositiveInt(maxFilesInput, filesCap);
    // A single-use link closes on its first file, whatever the field says.
    const maxFiles = parsed === undefined ? Math.min(10, filesCap) : parsed;
    if (maxFiles === null) {
      notice.error(t.maxFilesInvalid(formatInteger(filesCap)));
      maxFilesInput?.focus();
      return;
    }
    const expiresIn = expiryFrom(maybeId("request-expires-in", HTMLSelectElement), defaultExpiry);
    if (submit) submit.disabled = true;
    try {
      notice.status(t.creatingRequest);
      const key = await generateRequestKeyPair();
      const { request_id } = await api.createRequest({
        expires_in: expiresIn,
        max_files: maxFiles,
        max_bytes: maxBytes,
        single_use: singleUse,
      });
      try {
        await requestKeys.put(request_id, key);
      } catch (e) {
        // Never hand out a link whose files nobody could open. But if the ID
        // is already taken, it names an existing link: leave it alone
        // (audit 2026-11b L-7).
        if (!(e instanceof KeyIdTakenError)) void api.deleteRequest(request_id).catch(() => undefined);
        throw e;
      }
      void requestPersistence();
      // The fragment is the link's own public key, never a server value (FORMAT.md §8.8).
      const url = `${location.origin}/r/${request_id}#${encodeRequestFragment(key.publicKey)}`;
      notice.status(t.requestReady);
      bumpCount("link-count");
      showLink(
        { container: "request-result", input: "request-link", copy: "request-copy", expiry: "request-expiry" },
        url,
        expiryChoiceText(expiresIn),
      );
    } catch (e) {
      notice.status("");
      notice.error(e);
    } finally {
      if (submit) submit.disabled = false;
    }
  }
}

const main = pageRoot("dashboard");
if (main !== null) {
  revealJsOnly();
  initShare(main);
  initRequest(main);
}
