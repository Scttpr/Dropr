/**
 * Inbox (`/inbox`): list received files with their decrypted names, download
 * or delete them. Each entry opens with the key pair of the request link it
 * came through, kept in this browser (lib/request-keys.ts); entries whose
 * link was created in another browser are listed without a name and can only
 * be deleted here.
 * DOM contract: docs/PAGES.md §Inbox.
 *
 * @module
 */

import { plaintextSize } from "./crypto/index.ts";
import { type InboxEntry, type RequestSummary, api } from "./lib/api.ts";
import { type DecryptedFile, type InboxResult, decryptInbox } from "./lib/decrypt-names.ts";
import { Notice, byId, el, focusTo, pageRoot, revealJsOnly, warnBeforeUnload } from "./lib/dom.ts";
import { downloadToSink, openSink, prepareDownloadWorker } from "./lib/downloader.ts";
import { formatBytes, formatDate } from "./lib/format.ts";
import { t } from "./lib/i18n.ts";
import { DAMAGED } from "./lib/messages.ts";
import { type RequestKeyRecord, nowSeconds, requestKeysFor } from "./lib/request-keys.ts";
import { isAbortError } from "./lib/retry.ts";
import { ProgressPanel } from "./lib/transfer-ui.ts";

interface DeleteText {
  /** Accessible name of the file (its name, or a description when it has none). */
  readonly label: string;
  readonly confirm: string;
  readonly done: string;
}

function init(main: HTMLElement): void {
  revealJsOnly();
  const requestKeys = requestKeysFor(main);
  void prepareDownloadWorker();
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

  async function load(): Promise<void> {
    notice.status(t.loadingFiles);
    const listedAt = nowSeconds();
    let entries: InboxEntry[];
    let requests: RequestSummary[];
    try {
      [entries, requests] = await Promise.all([api.listInbox(), api.listRequests()]);
    } catch (e) {
      notice.status("");
      notice.error(e, false);
      return;
    }
    // Without a key store the files are still listed (and deletable); the error says why none opens.
    const keys = await requestKeys.prune(requests.map((r) => r.id), listedAt).catch((e: unknown) => {
      notice.error(e, false);
      return new Map<string, RequestKeyRecord>();
    });
    const results = await decryptInbox((id) => keys.get(id), entries);
    list.replaceChildren(...results.map(row));
    table.hidden = results.length === 0;
    empty.hidden = results.length !== 0;
    const count = (kind: InboxResult["kind"]): number => results.filter((r) => r.kind === kind).length;
    notice.status(t.filesReceived(results.length, count("unreadable"), count("foreign")));
  }

  function row(r: InboxResult): HTMLTableRowElement {
    const { entry } = r;
    const file = r.kind === "file" ? r.file : null;
    const date = formatDate(entry.created_at);
    const name = file?.meta.name ?? (r.kind === "foreign" ? t.foreignFile : t.unreadableFile);
    // Without a decrypted name, the date tells files apart for Delete.
    const text: DeleteText =
      r.kind === "foreign"
        ? { label: t.foreignFileNamed(date), confirm: t.confirmDeleteForeign(date), done: t.deletedForeign(date) }
        : { label: name, confirm: t.confirmDelete(name), done: t.deleted(name) };
    const size = (() => {
      try {
        return formatBytes(plaintextSize(entry.size));
      } catch {
        return "–";
      }
    })();
    const time = el("time", { text: date, attrs: { datetime: new Date(entry.created_at * 1000).toISOString() } });
    const dl = el("button", { text: t.download, attrs: { type: "button", "aria-label": t.downloadNamed(name) } });
    const del = el("button", { text: t.delete, class: "danger", attrs: { type: "button", "aria-label": t.deleteNamed(text.label) } });
    const unreadable = r.kind === "unreadable";
    const tr = el(
      "tr",
      { attrs: { "data-inbox-id": entry.id }, ...(r.kind === "foreign" ? { class: "foreign" } : {}) },
      el("td", { class: unreadable ? "name unreadable" : "name", text: name, attrs: unreadable ? { title: DAMAGED } : {} }),
      el("td", { class: "size", text: size }),
      el("td", { class: "date" }, time),
      el("td", { class: "actions" }, file !== null ? dl : null, " ", del),
    );
    if (file !== null) dl.addEventListener("click", () => void download(entry, file, dl));
    del.addEventListener("click", () => void remove(entry, text, tr, del));
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

  async function remove(entry: InboxEntry, text: DeleteText, tr: HTMLTableRowElement, button: HTMLButtonElement): Promise<void> {
    if (!confirm(text.confirm)) return;
    button.disabled = true;
    notice.clear();
    try {
      await api.deleteInbox(entry.id);
      const nextFocus = tr.nextElementSibling?.querySelector("button") ?? tr.previousElementSibling?.querySelector("button") ?? null;
      tr.remove();
      notice.status(text.done);
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

  void load();
}

const main = pageRoot("inbox");
if (main !== null) init(main);
