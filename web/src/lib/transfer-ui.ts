/**
 * Progress panel shared by uploads (dashboard, request page) and downloads
 * (share page, inbox): a `<progress>`, a polite live region with
 * percent/rate/ETA, Cancel and (uploads) Retry buttons.
 *
 * Live-region updates are throttled (every 10 % or 15 s) so screen readers
 * are not flooded; the `<progress>` element itself updates continuously.
 *
 * @module
 */

import { byId, maybeId } from "./dom.ts";
import { formatBytes, formatEta, formatRate, percent } from "./format.ts";
import type { Progress } from "./progress.ts";
import { isAbortError } from "./retry.ts";
import { UploadInterruptedError, type Uploader } from "./uploader.ts";

export interface PanelIds {
  readonly panel: string;
  readonly name?: string;
  readonly progress: string;
  readonly status: string;
  readonly cancel?: string;
  readonly retry?: string;
}

export class ProgressPanel {
  readonly panel: HTMLElement;
  private readonly nameEl: HTMLElement | null;
  private readonly bar: HTMLProgressElement;
  private readonly statusEl: HTMLElement;
  readonly cancelBtn: HTMLButtonElement | null;
  readonly retryBtn: HTMLButtonElement | null;
  private lastAnnounced = -100;
  private lastAnnouncedAt = 0;

  constructor(ids: PanelIds) {
    this.panel = byId(ids.panel);
    this.nameEl = ids.name !== undefined ? maybeId(ids.name) : null;
    this.bar = byId(ids.progress, HTMLProgressElement);
    this.statusEl = byId(ids.status);
    this.cancelBtn = ids.cancel !== undefined ? maybeId(ids.cancel, HTMLButtonElement) : null;
    this.retryBtn = ids.retry !== undefined ? maybeId(ids.retry, HTMLButtonElement) : null;
  }

  start(name: string, verb: string): void {
    this.panel.hidden = false;
    if (this.nameEl !== null) this.nameEl.textContent = name;
    this.bar.max = 100;
    this.bar.value = 0;
    this.bar.hidden = false;
    if (this.cancelBtn) {
      this.cancelBtn.hidden = false;
      this.cancelBtn.disabled = false;
    }
    if (this.retryBtn) this.retryBtn.hidden = true;
    this.lastAnnounced = -100;
    this.say(`${verb} ${name}…`);
  }

  update(p: Progress, verb: string): void {
    const pc = percent(p.done, p.total);
    this.bar.value = pc;
    this.bar.setAttribute("aria-valuetext", `${pc}%`);
    const now = Date.now();
    if (pc - this.lastAnnounced >= 10 || now - this.lastAnnouncedAt >= 15_000 || pc === 100) {
      this.lastAnnounced = pc;
      this.lastAnnouncedAt = now;
      const parts = [`${verb}: ${pc}%`, `${formatBytes(p.done)} of ${formatBytes(p.total)}`];
      if (p.rate > 0 && pc < 100) parts.push(formatRate(p.rate));
      const eta = pc < 100 ? formatEta(p.eta) : "";
      if (eta !== "") parts.push(eta);
      this.say(parts.join(" · "));
    }
  }

  say(text: string): void {
    this.statusEl.textContent = text;
  }

  finish(text: string): void {
    this.bar.value = 100;
    if (this.cancelBtn) this.cancelBtn.hidden = true;
    if (this.retryBtn) this.retryBtn.hidden = true;
    this.say(text);
  }

  hide(): void {
    this.panel.hidden = true;
  }
}

/**
 * Run an upload with the panel: Cancel aborts, an interruption shows Retry
 * and also resumes automatically when the browser comes back online.
 * Resolves when finalized; rejects on cancel (AbortError) or permanent error.
 */
export function runUploadWithPanel(uploader: Uploader, panel: ProgressPanel, name: string): Promise<void> {
  panel.start(name, "Encrypting and uploading");
  return new Promise<void>((resolve, reject) => {
    const onCancel = (): void => uploader.cancel();
    panel.cancelBtn?.addEventListener("click", onCancel);
    const cleanup = (): void => {
      panel.cancelBtn?.removeEventListener("click", onCancel);
      panel.retryBtn?.removeEventListener("click", attempt);
      window.removeEventListener("online", attempt);
    };
    const attempt = (): void => {
      if (uploader.status === "running") return;
      if (panel.retryBtn) panel.retryBtn.hidden = true;
      window.removeEventListener("online", attempt);
      panel.say(`Uploading ${name}…`);
      uploader.run().then(
        () => {
          cleanup();
          resolve();
        },
        (e: unknown) => {
          if (e instanceof UploadInterruptedError) {
            panel.say(e.message);
            if (panel.retryBtn) {
              panel.retryBtn.hidden = false;
              panel.retryBtn.focus();
            }
            window.addEventListener("online", attempt);
            return;
          }
          cleanup();
          if (isAbortError(e)) panel.say("Upload cancelled.");
          reject(e);
        },
      );
    };
    panel.retryBtn?.addEventListener("click", attempt);
    attempt();
  });
}
