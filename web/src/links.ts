/**
 * Active links (`/links`): share links (size, expiry, downloads, Revoke) and
 * request links (expiry, files received, Copy link, Revoke).
 * DOM contract: docs/PAGES.md §Links.
 *
 * Share names are not shown: they are encrypted under each file's FK, which
 * only the link holds (the owner's browser does not keep it). A request link
 * can be copied again in the browser that created it, because its fragment
 * is the public key stored there (lib/request-keys.ts); listing the links
 * also prunes the keys of links that are gone.
 *
 * @module
 */

import { TAG_SIZE, encodeRequestFragment, plaintextSize } from "./crypto/index.ts";
import { type RequestSummary, type ShareSummary, api } from "./lib/api.ts";
import { Notice, byId, copyText, el, focusTo, pageRoot, revealJsOnly } from "./lib/dom.ts";
import { formatBytes, formatDate, formatExpiry } from "./lib/format.ts";
import { t } from "./lib/i18n.ts";
import { type RequestKeyRecord, nowSeconds, requestKeysFor } from "./lib/request-keys.ts";

function size(cipher: number): string {
  try {
    return formatBytes(plaintextSize(cipher));
  } catch {
    return "–";
  }
}

function init(main: HTMLElement): void {
  revealJsOnly();
  const requestKeys = requestKeysFor(main);
  const notice = new Notice(byId("links-error"), byId("links-status"));

  interface RevokeText {
    /** Accessible name of the link ("share link created …"). */
    readonly label: string;
    readonly confirm: string;
    readonly done: string;
  }

  function revokeButton(text: RevokeText, del: () => Promise<void>, tr: HTMLTableRowElement): HTMLButtonElement {
    const b = el("button", { text: t.revoke, class: "danger", attrs: { type: "button", "aria-label": t.revokeNamed(text.label) } });
    b.addEventListener("click", async () => {
      if (!confirm(text.confirm)) return;
      b.disabled = true;
      notice.clear();
      try {
        await del();
        const body = tr.parentElement;
        const next = tr.nextElementSibling?.querySelector("button") ?? tr.previousElementSibling?.querySelector("button") ?? null;
        tr.remove();
        notice.status(text.done);
        if (body !== null && body.children.length === 0) {
          const table = body.closest("table");
          if (table instanceof HTMLElement) table.hidden = true;
          const emptyId = body.id === "shares-list" ? "shares-empty" : "requests-empty";
          const empty = byId(emptyId);
          empty.hidden = false;
          focusTo(empty);
        } else if (next instanceof HTMLButtonElement) next.focus();
      } catch (e) {
        b.disabled = false;
        notice.error(e);
      }
    });
    return b;
  }

  /** A short note on a link that no longer works although it has not expired. */
  function stateNote(text: string, hint: string): HTMLElement {
    return el("span", { class: "muted state", text, attrs: { title: hint } });
  }

  function shareRow(s: ShareSummary): HTMLTableRowElement {
    const label = t.shareLinkLabel(formatDate(s.created_at));
    const exhausted = s.max_downloads !== null && s.download_count >= s.max_downloads;
    const tr = el("tr", { attrs: { "data-share-id": s.id } });
    tr.append(
      el("td", { class: "size", text: size(s.size) }),
      el("td", { class: "date", text: formatDate(s.created_at) }),
      el("td", { class: "expiry", text: formatExpiry(s.expires_at) }),
      el(
        "td",
        { class: "downloads" },
        s.max_downloads === null ? String(s.download_count) : t.countOf(s.download_count, s.max_downloads),
        exhausted && " ",
        exhausted && stateNote(t.limitReached, t.limitReachedHint),
      ),
      el(
        "td",
        { class: "actions" },
        revokeButton({ label, confirm: t.confirmRevokeShare, done: t.shareRevoked }, () => api.deleteShare(s.id), tr),
      ),
    );
    return tr;
  }

  /** Copy link, or a note when this browser does not hold the link's key (the fragment is never a server value). */
  function copyControl(r: RequestSummary, key: RequestKeyRecord | undefined, label: string): HTMLElement {
    if (key === undefined) return el("span", { class: "muted", text: t.otherBrowser, attrs: { title: t.otherBrowserHint } });
    const copy = el("button", { text: t.copyLink, attrs: { type: "button", "aria-label": t.copyLinkNamed(label) } });
    copy.addEventListener("click", async () => {
      notice.clear();
      const ok = await copyText(`${location.origin}/r/${r.id}#${encodeRequestFragment(key.publicKey)}`);
      notice.status(ok ? t.requestCopied : t.copyFailed);
    });
    return copy;
  }

  async function revokeRequest(id: string): Promise<void> {
    await api.deleteRequest(id);
    // Best effort: a leftover record is pruned at the next listing.
    await requestKeys.delete(id).catch(() => undefined);
  }

  function requestRow(r: RequestSummary, key: RequestKeyRecord | undefined): HTMLTableRowElement {
    const label = t.requestLinkLabel(formatDate(r.created_at));
    // Same test as the server's uploader page: no room left for one more (empty) file.
    const closed = r.closed || r.files_received >= r.max_files || r.max_bytes - r.bytes_received < TAG_SIZE;
    const tr = el("tr", { attrs: { "data-request-id": r.id } });
    tr.append(
      el("td", { class: "date", text: formatDate(r.created_at) }),
      el("td", { class: "expiry", text: formatExpiry(r.expires_at) }),
      el(
        "td",
        { class: "files" },
        t.countOf(r.files_received, r.max_files) + (r.single_use ? t.singleUse : ""),
        closed && " ",
        closed && stateNote(t.linkClosed, t.linkClosedHint),
      ),
      el(
        "td",
        { class: "actions" },
        // A closed link is useless to whoever receives it: nothing to copy.
        !closed && copyControl(r, key, label),
        !closed && " ",
        revokeButton({ label, confirm: t.confirmRevokeRequest, done: t.requestRevoked }, () => revokeRequest(r.id), tr),
      ),
    );
    return tr;
  }

  async function load(): Promise<void> {
    notice.status(t.loadingLinks);
    try {
      const listedAt = nowSeconds();
      const [shares, requests] = await Promise.all([api.listShares(), api.listRequests()]);
      // Without a key store the links are still listed (and revocable); the error says why none can be copied.
      const keys = await requestKeys.prune(requests.map((r) => r.id), listedAt).catch((e: unknown) => {
        notice.error(e, false);
        return new Map<string, RequestKeyRecord>();
      });
      byId("shares-list").replaceChildren(...shares.map(shareRow));
      byId("shares-table").hidden = shares.length === 0;
      byId("shares-empty").hidden = shares.length !== 0;
      byId("requests-list").replaceChildren(...requests.map((r) => requestRow(r, keys.get(r.id))));
      byId("requests-table").hidden = requests.length === 0;
      byId("requests-empty").hidden = requests.length !== 0;
      notice.status(t.linksSummary(shares.length, requests.length));
    } catch (e) {
      notice.status("");
      notice.error(e, false);
    }
  }

  void load();
}

const main = pageRoot("links");
if (main !== null) init(main);
