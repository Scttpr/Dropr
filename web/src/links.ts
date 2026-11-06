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

  function revokeButton(label: string, what: string, del: () => Promise<void>, tr: HTMLTableRowElement): HTMLButtonElement {
    const b = el("button", { text: "Revoke", class: "danger", attrs: { type: "button", "aria-label": `Revoke ${label}` } });
    b.addEventListener("click", async () => {
      if (!confirm(`Revoke this ${what}? It stops working immediately and its files are deleted.`)) return;
      b.disabled = true;
      notice.clear();
      try {
        await del();
        const body = tr.parentElement;
        const next = tr.nextElementSibling?.querySelector("button") ?? tr.previousElementSibling?.querySelector("button") ?? null;
        tr.remove();
        notice.status(`${what[0]?.toUpperCase()}${what.slice(1)} revoked.`);
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
    const label = `share link created ${formatDate(s.created_at)}`;
    const tr = el("tr", { attrs: { "data-share-id": s.id } });
    tr.append(
      el("td", { class: "size", text: size(s.size) }),
      el("td", { class: "date", text: formatDate(s.created_at) }),
      el("td", { class: "expiry", text: formatExpiry(s.expires_at) }),
      el("td", {
        class: "downloads",
        text: s.max_downloads === null ? String(s.download_count) : `${s.download_count} of ${s.max_downloads}`,
      }),
      el("td", { class: "actions" }, revokeButton(label, "share link", () => api.deleteShare(s.id), tr)),
    );
    return tr;
  }

  function requestRow(r: RequestSummary): HTMLTableRowElement {
    const label = `request link created ${formatDate(r.created_at)}`;
    const tr = el("tr", { attrs: { "data-request-id": r.id } });
    const copy = el("button", { text: "Copy link", attrs: { type: "button", "aria-label": `Copy link: ${label}` } });
    copy.addEventListener("click", async () => {
      notice.clear();
      try {
        const key = await ensureUnlocked();
        const ok = await copyText(`${location.origin}/r/${r.id}#${encodeRequestFragment(key.publicKey)}`);
        notice.status(ok ? "Request link copied." : "Could not copy the link to the clipboard.");
      } catch (e) {
        notice.error(e);
      }
    });
    tr.append(
      el("td", { class: "date", text: formatDate(r.created_at) }),
      el("td", { class: "expiry", text: formatExpiry(r.expires_at) }),
      el("td", { class: "files", text: `${r.files_received} of ${r.max_files}${r.single_use ? " (single use)" : ""}` }),
      el("td", { class: "actions" }, copy, " ", revokeButton(label, "request link", () => api.deleteRequest(r.id), tr)),
    );
    return tr;
  }

  async function load(): Promise<void> {
    notice.status("Loading your links…");
    try {
      const [shares, requests] = await Promise.all([api.listShares(), api.listRequests()]);
      byId("shares-list").replaceChildren(...shares.map(shareRow));
      byId("shares-table").hidden = shares.length === 0;
      byId("shares-empty").hidden = shares.length !== 0;
      byId("requests-list").replaceChildren(...requests.map(requestRow));
      byId("requests-table").hidden = requests.length === 0;
      byId("requests-empty").hidden = requests.length !== 0;
      notice.status(
        `${shares.length} share link${shares.length === 1 ? "" : "s"}, ${requests.length} request link${requests.length === 1 ? "" : "s"}.`,
      );
    } catch (e) {
      notice.status("");
      notice.error(e, false);
    }
  }

  void load();
}

if (pageRoot("links") !== null) init();
