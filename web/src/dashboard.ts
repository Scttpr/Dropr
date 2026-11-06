/**
 * Dashboard (`/`): share a file (flow A) and create a request link (flow B).
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
  partCount,
  sealMeta,
} from "./crypto/index.ts";
import { EXPIRY_CHOICES, type ExpiresIn, api } from "./lib/api.ts";
import { Notice, byId, dataInt, maybeId, pageRoot, revealJsOnly, warnBeforeUnload } from "./lib/dom.ts";
import { attachDropZone } from "./lib/dropzone.ts";
import { expiryChoiceText, formatBytes } from "./lib/format.ts";
import { showLink } from "./lib/linkview.ts";
import { ensureUnlocked } from "./lib/passkey.ts";
import { isAbortError } from "./lib/retry.ts";
import { ProgressPanel, runUploadWithPanel } from "./lib/transfer-ui.ts";
import { Uploader } from "./lib/uploader.ts";

function isExpiry(v: string | undefined): v is ExpiresIn {
  return v !== undefined && (EXPIRY_CHOICES as readonly string[]).includes(v);
}

function expiryFrom(select: HTMLSelectElement | null, fallback: ExpiresIn): ExpiresIn {
  const v = select?.value;
  return isExpiry(v) ? v : fallback;
}

/** `data-default-expiry` if valid, else 7 days (PLAN.md §6). */
function defaultExpiryOf(main: HTMLElement): ExpiresIn {
  const d = main.dataset["defaultExpiry"];
  return isExpiry(d) ? d : "7d";
}

function optionalPositiveInt(input: HTMLInputElement | null): number | undefined | null {
  const raw = input?.value.trim() ?? "";
  if (raw === "") return undefined;
  if (!/^\d{1,6}$/.test(raw) || Number(raw) < 1) return null; // invalid
  return Number(raw);
}

function initShare(main: HTMLElement): void {
  const maxSize = dataInt(main, "maxFileSize", 5_000_000_000);
  const defaultExpiry = defaultExpiryOf(main);
  const form = byId("share-form", HTMLFormElement);
  const expirySel = maybeId("expires-in", HTMLSelectElement);
  const maxDl = maybeId("max-downloads", HTMLInputElement);
  const notice = new Notice(byId("share-error"));
  const panel = new ProgressPanel({
    panel: "upload-panel",
    name: "upload-file-name",
    progress: "upload-progress",
    status: "upload-status",
    cancel: "upload-cancel",
    retry: "upload-retry",
  });
  const result = byId("share-result");
  let busy = false;
  warnBeforeUnload(() => busy);
  form.addEventListener("submit", (ev) => ev.preventDefault());

  const zone = attachDropZone(byId("drop-zone"), byId("file-input", HTMLInputElement), (files) => {
    const file = files[0];
    if (file !== undefined) void share(file);
  });

  maybeId("share-another", HTMLButtonElement)?.addEventListener("click", () => {
    result.hidden = true;
    panel.hide();
    form.hidden = false;
    byId("file-input", HTMLInputElement).focus();
  });

  async function share(file: File): Promise<void> {
    if (busy) return;
    notice.clear();
    if (file.size > maxSize) {
      const limit = formatBytes(maxSize);
      // Just over the limit both round to the same figure; show the exact size instead.
      const have = formatBytes(file.size) === limit ? `${file.size.toLocaleString("en-US")} bytes` : formatBytes(file.size);
      notice.error(`This file is too large (${have}). The limit is ${limit}.`);
      return;
    }
    const maxDownloads = optionalPositiveInt(maxDl);
    if (maxDownloads === null) {
      notice.error("The download limit must be a whole number of at least 1, or empty for no limit.");
      maxDl?.focus();
      return;
    }
    const expiresIn = expiryFrom(expirySel, defaultExpiry);
    busy = true;
    zone.setEnabled(false);
    result.hidden = true;
    let shareId: string | null = null;
    let finished = false;
    try {
      const fk = generateFileKey();
      const keys = await deriveFileKeys(fk);
      const meta = await sealMeta(keys.metadata, { name: file.name, type: file.type, size: file.size });
      const size = ciphertextSize(file.size);
      const created = await api.createShare({
        size,
        parts: partCount(size),
        meta: b64urlEncode(meta),
        expires_in: expiresIn,
        ...(maxDownloads !== undefined ? { max_downloads: maxDownloads } : {}),
      });
      shareId = created.share_id;
      form.hidden = true;
      const uploader = new Uploader({
        file,
        contentKey: keys.content,
        uploadId: created.upload_id,
        uploadToken: created.upload_token,
        onProgress: (p) => panel.update(p, "Uploading"),
      });
      await runUploadWithPanel(uploader, panel, file.name);
      finished = true;
      const url = `${location.origin}/s/${created.share_id}#${encodeShareFragment(fk)}`;
      fk.fill(0);
      panel.finish("Upload complete. Your link is ready.");
      bumpCount("link-count");
      showLink(
        { container: "share-result", input: "share-link", copy: "share-copy", expiry: "share-expiry", qr: "share-qr" },
        url,
        expiryChoiceText(expiresIn),
        "QR code of the share link",
      );
    } catch (e) {
      if (!isAbortError(e)) notice.error(e);
      panel.hide();
      form.hidden = false;
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

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void create();
  });

  async function create(): Promise<void> {
    notice.clear();
    const maxFilesInput = maybeId("request-max-files", HTMLInputElement);
    const parsed = optionalPositiveInt(maxFilesInput);
    const maxFiles = parsed === undefined ? 10 : parsed;
    if (maxFiles === null) {
      notice.error("The number of files must be a whole number of at least 1.");
      maxFilesInput?.focus();
      return;
    }
    const expiresIn = expiryFrom(maybeId("request-expires-in", HTMLSelectElement), defaultExpiry);
    const singleUse = maybeId("request-single-use", HTMLInputElement)?.checked ?? false;
    if (submit) submit.disabled = true;
    try {
      notice.status("Unlocking with your passkey…");
      const key = await ensureUnlocked();
      notice.status("Creating the request link…");
      const { request_id } = await api.createRequest({
        expires_in: expiresIn,
        max_files: maxFiles,
        max_bytes: maxBytes,
        single_use: singleUse,
      });
      // The public key comes from the authenticated, unwrapped JWK (FORMAT.md §8.8).
      const url = `${location.origin}/r/${request_id}#${encodeRequestFragment(key.publicKey)}`;
      notice.status("Your request link is ready.");
      bumpCount("link-count");
      showLink(
        { container: "request-result", input: "request-link", copy: "request-copy", expiry: "request-expiry", qr: "request-qr" },
        url,
        expiryChoiceText(expiresIn),
        "QR code of the request link",
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
