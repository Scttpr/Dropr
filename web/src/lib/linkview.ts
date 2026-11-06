/**
 * Show a freshly created link: read-only text field, Copy button (Clipboard
 * API, falling back to selecting the text) and expiry line.
 *
 * @module
 */

import { byId, copyText, focusTo, maybeId } from "./dom.ts";
import { t } from "./i18n.ts";

export interface LinkViewIds {
  /** Container, rendered `hidden`. */
  readonly container: string;
  readonly input: string;
  readonly copy: string;
  readonly expiry?: string;
}

/** Fill and reveal the link container; focus moves to the link field. */
export function showLink(ids: LinkViewIds, url: string, expiryText: string): void {
  const container = byId(ids.container);
  const input = byId(ids.input, HTMLInputElement);
  const copy = byId(ids.copy, HTMLButtonElement);
  input.value = url;
  input.readOnly = true;
  input.addEventListener("focus", () => input.select());
  const label = copy.textContent ?? "";
  copy.onclick = async () => {
    const ok = await copyText(url, input);
    copy.textContent = ok ? t.copied : t.pressToCopy;
    setTimeout(() => (copy.textContent = label), 2500);
  };
  const exp = ids.expiry !== undefined ? maybeId(ids.expiry) : null;
  if (exp !== null) exp.textContent = expiryText;
  container.hidden = false;
  focusTo(input);
}
