/**
 * Request uploader page (`/r/{id}#<owner pubkey>`): anyone with the link can
 * send files that only the owner can read.
 * DOM contract: docs/PAGES.md §Request.
 *
 * Per file: fresh FK → seal metadata → HPKE-wrap FK to the owner's public key
 * (from the fragment, never from the server) bound to the request id →
 * `POST /api/r/{id}/files` → upload parts → finalize. Files are sent one
 * after the other.
 *
 * @module
 */

import {
  b64urlEncode,
  ciphertextSize,
  decodeRequestFragment,
  deriveFileKeys,
  generateFileKey,
  partCount,
  sealMeta,
  wrapFileKeyForRequest,
} from "./crypto/index.ts";
import { api } from "./lib/api.ts";
import { Notice, byId, dataInt, el, focusTo, maybeId, pageRoot, revealJsOnly, warnBeforeUnload } from "./lib/dom.ts";
import { attachDropZone } from "./lib/dropzone.ts";
import { formatBytes } from "./lib/format.ts";
import { errorMessage } from "./lib/messages.ts";
import { isAbortError } from "./lib/retry.ts";
import { ProgressPanel, runUploadWithPanel } from "./lib/transfer-ui.ts";
import { Uploader } from "./lib/uploader.ts";

function init(main: HTMLElement): void {
  revealJsOnly();
  const requestId = main.dataset["requestId"] ?? "";
  const notice = new Notice(byId("upload-error"), null);
  const zoneEl = byId("drop-zone");
  const input = byId("file-input", HTMLInputElement);
  const doneEl = byId("upload-done");
  const list = maybeId("upload-list");
  const panel = new ProgressPanel({
    panel: "upload-panel",
    name: "upload-file-name",
    progress: "upload-progress",
    status: "upload-status",
    cancel: "upload-cancel",
    retry: "upload-retry",
  });
  const maxBytes = dataInt(main, "maxBytes", Number.MAX_SAFE_INTEGER); // plaintext bytes still accepted
  let filesLeft = dataInt(main, "maxFiles", Number.MAX_SAFE_INTEGER);
  let bytesLeft = maxBytes;

  let ownerKey: Uint8Array;
  try {
    ownerKey = decodeRequestFragment(location.hash);
  } catch {
    zoneEl.hidden = true;
    notice.error("This link is incomplete or damaged. Ask the person who sent it for the complete link.", false);
    return;
  }

  let busy = false;
  warnBeforeUnload(() => busy);
  const zone = attachDropZone(zoneEl, input, (files) => void sendAll(files), { multiple: true });

  async function sendAll(files: File[]): Promise<void> {
    if (busy) return;
    notice.clear();
    doneEl.hidden = true;
    if (files.length > filesLeft) {
      notice.error(
        filesLeft === 0
          ? "This link does not accept more files."
          : `This link accepts ${filesLeft} more file${filesLeft === 1 ? "" : "s"}. Please choose fewer files.`,
      );
      return;
    }
    const total = files.reduce((n, f) => n + f.size, 0);
    if (total > bytesLeft) {
      notice.error(`These files are too large (${formatBytes(total)}). This link accepts up to ${formatBytes(bytesLeft)} more.`);
      return;
    }
    busy = true;
    zone.setEnabled(false);
    let sent = 0;
    try {
      for (const file of files) {
        await sendOne(file);
        sent++;
        filesLeft--;
        bytesLeft -= file.size;
        list?.append(el("li", { text: `${file.name} (${formatBytes(file.size)}) — sent` }));
      }
      panel.hide();
      doneEl.hidden = false;
      focusTo(doneEl);
    } catch (e) {
      panel.hide();
      if (isAbortError(e)) notice.error(sent > 0 ? `Cancelled. ${sent} file${sent === 1 ? " was" : "s were"} sent before.` : "Cancelled.");
      else notice.error(sent > 0 ? `${errorMessage(e)} ${sent} file${sent === 1 ? " was" : "s were"} sent before the error.` : e);
    } finally {
      busy = false;
      zone.setEnabled(filesLeft > 0);
    }
  }

  async function sendOne(file: File): Promise<void> {
    const fk = generateFileKey();
    try {
      const keys = await deriveFileKeys(fk);
      const meta = await sealMeta(keys.metadata, { name: file.name, type: file.type, size: file.size });
      const wrapped = await wrapFileKeyForRequest(ownerKey, requestId, fk);
      const size = ciphertextSize(file.size);
      const created = await api.createRequestFile(requestId, {
        size,
        parts: partCount(size),
        meta: b64urlEncode(meta),
        wrapped_key: b64urlEncode(wrapped),
      });
      const uploader = new Uploader({
        file,
        contentKey: keys.content,
        uploadId: created.upload_id,
        uploadToken: created.upload_token,
        onProgress: (p) => panel.update(p, "Uploading"),
      });
      await runUploadWithPanel(uploader, panel, file.name);
    } finally {
      fk.fill(0);
    }
  }
}

const main = pageRoot("request");
if (main !== null) init(main);
