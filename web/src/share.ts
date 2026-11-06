/**
 * Share recipient page (`/s/{id}#<fk>`): decrypt the file name from the link
 * fragment, then stream-download and decrypt on click.
 * DOM contract: docs/PAGES.md §Share.
 *
 * Fetching the download token on load does not count as a download (the
 * server counts on first use of the token), so the name can be shown before
 * the click.
 *
 * @module
 */

import { DecryptionError, FormatError, decodeShareFragment } from "./crypto/index.ts";
import { ApiError, type ShareDownload, api } from "./lib/api.ts";
import { type DecryptedFile, openShare } from "./lib/decrypt-names.ts";
import { Notice, byId, dataInt, maybeId, pageRoot, revealJsOnly, warnBeforeUnload } from "./lib/dom.ts";
import { downloadToSink, openSink, prepareDownloadWorker } from "./lib/downloader.ts";
import { formatBytes, formatExpiry } from "./lib/format.ts";
import { t } from "./lib/i18n.ts";
import { DAMAGED } from "./lib/messages.ts";
import { isAbortError } from "./lib/retry.ts";
import { ProgressPanel } from "./lib/transfer-ui.ts";

/** Plain-language message for share-link API errors. */
export function shareErrorMessage(e: unknown): string | null {
  if (!(e instanceof ApiError)) return null;
  if (e.code === "expired") return t.statusExpired;
  if (e.code === "exhausted") return t.statusExhausted;
  if (e.status === 404) return t.shareNotFound;
  if (e.status === 410) return t.shareGone;
  return null;
}

async function init(main: HTMLElement): Promise<void> {
  revealJsOnly();
  const shareId = main.dataset["shareId"] ?? "";
  const notice = new Notice(byId("download-error"), null);
  const button = byId("download-button", HTMLButtonElement);
  const nameEl = byId("file-name");
  const sizeEl = maybeId("file-size");
  const expiryEl = maybeId("file-expiry");
  const panel = new ProgressPanel({
    panel: "download-panel",
    progress: "download-progress",
    status: "download-status",
    cancel: "download-cancel",
  });
  const fail = (msg: string): void => {
    button.hidden = true;
    notice.error(msg, false);
  };
  button.disabled = true;

  const expiresAt = dataInt(main, "expiresAt", 0);
  if (expiresAt > 0 && expiryEl !== null) expiryEl.textContent = formatExpiry(expiresAt);

  let fk: Uint8Array;
  try {
    fk = decodeShareFragment(location.hash);
  } catch {
    fail(
      location.hash.length <= 1 ? t.missingKey : t.incompleteLink,
    );
    return;
  }

  void prepareDownloadWorker();
  let info: ShareDownload;
  let file: DecryptedFile;
  try {
    panel.say(t.checkingLink);
    info = await api.shareDownload(shareId);
    file = await openShare(fk, info.meta, info.size);
    fk.fill(0);
  } catch (e) {
    panel.say("");
    if (e instanceof DecryptionError || e instanceof FormatError) fail(t.wrongKey);
    else fail(shareErrorMessage(e) ?? (e instanceof ApiError ? e.message : DAMAGED));
    return;
  }
  panel.say("");
  nameEl.textContent = file.meta.name;
  if (sizeEl !== null) sizeEl.textContent = formatBytes(file.meta.size);
  document.title = `${file.meta.name} – Dropr`;
  button.disabled = false;

  let ctl: AbortController | null = null;
  warnBeforeUnload(() => ctl !== null);
  panel.cancelBtn?.addEventListener("click", () => ctl?.abort());

  button.addEventListener("click", async () => {
    if (ctl !== null) return;
    notice.clear();
    ctl = new AbortController();
    button.disabled = true;
    try {
      const { sink, notice: sinkNotice } = await openSink(file.meta.name, file.meta.size); // first await: user gesture
      panel.start(file.meta.name, t.downloading);
      if (sinkNotice !== "") panel.say(sinkNotice);
      const signal = ctl.signal;
      let token = info.token;
      await downloadToSink({
        token,
        cipherSize: info.size,
        contentKey: file.keys.content,
        sink,
        signal,
        onProgress: (p) => panel.update(p, t.downloading),
        renewToken: async () => {
          token = (await api.shareDownload(shareId, { signal })).token;
          return token;
        },
      });
      panel.finish(sink.kind === "sw" ? t.downloadCompleteCheck : t.downloadComplete);
      // A token is single-file but may be reused for Range resumes only within its TTL; get a fresh one for a second click.
      info = await api.shareDownload(shareId).catch(() => info);
    } catch (e) {
      if (isAbortError(e)) panel.finish(t.downloadCancelled);
      else {
        panel.hide();
        notice.error(shareErrorMessage(e) ?? e);
      }
    } finally {
      ctl = null;
      button.disabled = false;
    }
  });
}

const main = pageRoot("share");
if (main !== null) void init(main);
