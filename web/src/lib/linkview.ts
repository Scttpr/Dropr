/**
 * Show a freshly created link: read-only text field, Copy button (Clipboard
 * API, falling back to selecting the text), expiry line and QR code.
 *
 * @module
 */

import { byId, copyText, focusTo, maybeId } from "./dom.ts";
import { encodeQr, qrToSvg } from "./qr.ts";

export interface LinkViewIds {
  /** Container, rendered `hidden`. */
  readonly container: string;
  readonly input: string;
  readonly copy: string;
  readonly expiry?: string;
  readonly qr?: string;
}

/** Fill and reveal the link container; focus moves to the link field. */
export function showLink(ids: LinkViewIds, url: string, expiryText: string, qrLabel: string): void {
  const container = byId(ids.container);
  const input = byId(ids.input, HTMLInputElement);
  const copy = byId(ids.copy, HTMLButtonElement);
  input.value = url;
  input.readOnly = true;
  input.addEventListener("focus", () => input.select());
  const label = copy.textContent ?? "Copy";
  copy.onclick = async () => {
    const ok = await copyText(url, input);
    copy.textContent = ok ? "Copied" : "Press Ctrl+C to copy";
    setTimeout(() => (copy.textContent = label), 2500);
  };
  const exp = ids.expiry !== undefined ? maybeId(ids.expiry) : null;
  if (exp !== null) exp.textContent = expiryText;
  const qrBox = ids.qr !== undefined ? maybeId(ids.qr) : null;
  if (qrBox !== null) {
    qrBox.replaceChildren();
    try {
      qrBox.append(qrToSvg(encodeQr(url), document, qrLabel));
    } catch {
      // Too long for a version-10 code: skip the QR, the link still works.
    }
  }
  container.hidden = false;
  focusTo(input);
}
