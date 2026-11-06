/**
 * Inbox (`/inbox`): unlock with a passkey, list received files with their
 * decrypted names, download or delete them.
 * DOM contract: docs/PAGES.md §Inbox.
 *
 * @module
 */

import { plaintextSize } from "./crypto/index.ts";
import { type InboxEntry, api } from "./lib/api.ts";
import { type DecryptedFile, decryptInbox } from "./lib/decrypt-names.ts";
import { Notice, byId, el, focusTo, pageRoot, revealJsOnly, warnBeforeUnload } from "./lib/dom.ts";
import { downloadToSink, openSink, prepareDownloadWorker } from "./lib/downloader.ts";
import { formatBytes, formatDate } from "./lib/format.ts";
import { t } from "./lib/i18n.ts";
import { DAMAGED } from "./lib/messages.ts";
import { ensureUnlocked, unlockedKey } from "./lib/passkey.ts";
import { isAbortError } from "./lib/retry.ts";
import { ProgressPanel } from "./lib/transfer-ui.ts";

function init(): void {
  revealJsOnly();
  void prepareDownloadWorker();
  const unlockBtn = byId("inbox-unlock", HTMLButtonElement);
  const notice = new Notice(byId("inbox-error"), byId("inbox-status"));
  const table = byId("inbox-table");
  const list = byId("inbox-list");
  const empty = byId("inbox-empty");
  const panel = new ProgressPanel({
    panel: "download-panel",
    name: "download-file-name",
    progress: "download-progress",
    status: "download-status",
    cancel: "download-cancel",
  });
  let downloading: AbortController | null = null;
  warnBeforeUnload(() => downloading !== null);
  panel.cancelBtn?.addEventListener("click", () => downloading?.abort());

  unlockBtn.addEventListener("click", async () => {
    unlockBtn.disabled = true;
    notice.clear();
    try {
      notice.status(t.unlocking);
      await ensureUnlocked();
      unlockBtn.hidden = true;
      await load();
    } catch (e) {
      notice.status("");
      notice.error(e);
      unlockBtn.disabled = false;
    }
  });

  async function load(): Promise<void> {
    const key = unlockedKey();
    if (key === null) return;
    notice.status(t.loadingFiles);
    const entries = await api.listInbox();
    const results = await decryptInbox(key, entries);
    list.replaceChildren(...results.map((r) => row(r.entry, r.ok ? r.file : null)));
    table.hidden = results.length === 0;
    empty.hidden = results.length !== 0;
    const failed = results.filter((r) => !r.ok).length;
    notice.status(t.filesReceived(results.length, failed));
    const firstButton = list.querySelector("button");
    if (firstButton instanceof HTMLButtonElement) focusTo(firstButton);
  }

  function row(entry: InboxEntry, file: DecryptedFile | null): HTMLTableRowElement {
    const name = file?.meta.name ?? t.unreadableFile;
    const size = (() => {
      try {
        return formatBytes(plaintextSize(entry.size));
      } catch {
        return "–";
      }
    })();
    const time = el("time", { text: formatDate(entry.created_at), attrs: { datetime: new Date(entry.created_at * 1000).toISOString() } });
    const dl = el("button", { text: t.download, attrs: { type: "button", "aria-label": t.downloadNamed(name) } });
    const del = el("button", { text: t.delete, class: "danger", attrs: { type: "button", "aria-label": t.deleteNamed(name) } });
    const tr = el(
      "tr",
      { attrs: { "data-inbox-id": entry.id } },
      el("td", { class: file === null ? "name unreadable" : "name", text: name, attrs: file === null ? { title: DAMAGED } : {} }),
      el("td", { class: "size", text: size }),
      el("td", { class: "date" }, time),
      el("td", { class: "actions" }, file !== null ? dl : null, " ", del),
    );
    if (file !== null) dl.addEventListener("click", () => void download(entry, file, dl));
    del.addEventListener("click", () => void remove(entry, name, tr, del));
    return tr;
  }

  async function download(entry: InboxEntry, file: DecryptedFile, button: HTMLButtonElement): Promise<void> {
    if (downloading !== null) {
      notice.error(t.anotherDownload);
      return;
    }
    notice.clear();
    const ctl = new AbortController();
    downloading = ctl;
    button.disabled = true;
    try {
      // First await: the save dialog needs the click's user activation.
      const { sink, notice: sinkNotice } = await openSink(file.meta.name, file.meta.size);
      panel.start(file.meta.name, t.downloading);
      if (sinkNotice !== "") notice.status(sinkNotice);
      const { token } = await api.inboxDownload(entry.id, { signal: ctl.signal });
      await downloadToSink({
        token,
        cipherSize: entry.size,
        contentKey: file.keys.content,
        sink,
        signal: ctl.signal,
        onProgress: (p) => panel.update(p, t.downloading),
        renewToken: async () => (await api.inboxDownload(entry.id, { signal: ctl.signal })).token,
      });
      panel.finish(sink.kind === "sw" ? t.downloadCompleteCheck : t.downloadComplete);
    } catch (e) {
      if (isAbortError(e)) panel.finish(t.downloadCancelled);
      else {
        panel.hide();
        notice.error(e);
      }
    } finally {
      downloading = null;
      button.disabled = false;
    }
  }

  async function remove(entry: InboxEntry, name: string, tr: HTMLTableRowElement, button: HTMLButtonElement): Promise<void> {
    if (!confirm(t.confirmDelete(name))) return;
    button.disabled = true;
    notice.clear();
    try {
      await api.deleteInbox(entry.id);
      const nextFocus = tr.nextElementSibling?.querySelector("button") ?? tr.previousElementSibling?.querySelector("button") ?? null;
      tr.remove();
      notice.status(t.deleted(name));
      if (list.children.length === 0) {
        table.hidden = true;
        empty.hidden = false;
        focusTo(empty);
      } else if (nextFocus instanceof HTMLButtonElement) {
        nextFocus.focus();
      }
    } catch (e) {
      button.disabled = false;
      notice.error(e);
    }
  }
}

if (pageRoot("inbox") !== null) init();
