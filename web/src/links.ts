/**
 * Active links (`/links`): share links (size, expiry, downloads, Revoke) and
 * request links (expiry, files received, Copy link, Revoke).
 * DOM contract: docs/PAGES.md §Links.
 *
 * Share names are not shown: they are encrypted under each file's FK, which
 * only the link holds (the owner's browser does not keep it). Request links
 * can be copied again after unlocking, because their fragment is the
 * owner's own public key, taken from the unlocked key pair.
 *
 * @module
 */

import { encodeRequestFragment, plaintextSize } from "./crypto/index.ts";
import { type RequestSummary, type ShareSummary, api } from "./lib/api.ts";
import { Notice, byId, copyText, el, focusTo, pageRoot, revealJsOnly } from "./lib/dom.ts";
import { formatBytes, formatDate, formatExpiry } from "./lib/format.ts";
import { t } from "./lib/i18n.ts";
import { ensureUnlocked } from "./lib/passkey.ts";

function size(cipher: number): string {
  try {
    return formatBytes(plaintextSize(cipher));
  } catch {
    return "–";
  }
}

function init(): void {
  revealJsOnly();
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

  function shareRow(s: ShareSummary): HTMLTableRowElement {
    const label = t.shareLinkLabel(formatDate(s.created_at));
    const tr = el("tr", { attrs: { "data-share-id": s.id } });
    tr.append(
      el("td", { class: "size", text: size(s.size) }),
      el("td", { class: "date", text: formatDate(s.created_at) }),
      el("td", { class: "expiry", text: formatExpiry(s.expires_at) }),
      el("td", {
        class: "downloads",
        text: s.max_downloads === null ? String(s.download_count) : t.countOf(s.download_count, s.max_downloads),
      }),
      el(
        "td",
        { class: "actions" },
        revokeButton({ label, confirm: t.confirmRevokeShare, done: t.shareRevoked }, () => api.deleteShare(s.id), tr),
      ),
    );
    return tr;
  }

  function requestRow(r: RequestSummary): HTMLTableRowElement {
    const label = t.requestLinkLabel(formatDate(r.created_at));
    const tr = el("tr", { attrs: { "data-request-id": r.id } });
    const copy = el("button", { text: t.copyLink, attrs: { type: "button", "aria-label": t.copyLinkNamed(label) } });
    copy.addEventListener("click", async () => {
      notice.clear();
      try {
        const key = await ensureUnlocked();
        const ok = await copyText(`${location.origin}/r/${r.id}#${encodeRequestFragment(key.publicKey)}`);
        notice.status(ok ? t.requestCopied : t.copyFailed);
      } catch (e) {
        notice.error(e);
      }
    });
    tr.append(
      el("td", { class: "date", text: formatDate(r.created_at) }),
      el("td", { class: "expiry", text: formatExpiry(r.expires_at) }),
      el("td", { class: "files", text: t.countOf(r.files_received, r.max_files) + (r.single_use ? t.singleUse : "") }),
      el(
        "td",
        { class: "actions" },
        copy,
        " ",
        revokeButton({ label, confirm: t.confirmRevokeRequest, done: t.requestRevoked }, () => api.deleteRequest(r.id), tr),
      ),
    );
    return tr;
  }

  async function load(): Promise<void> {
    notice.status(t.loadingLinks);
    try {
      const [shares, requests] = await Promise.all([api.listShares(), api.listRequests()]);
      byId("shares-list").replaceChildren(...shares.map(shareRow));
      byId("shares-table").hidden = shares.length === 0;
      byId("shares-empty").hidden = shares.length !== 0;
      byId("requests-list").replaceChildren(...requests.map(requestRow));
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

if (pageRoot("links") !== null) init();
