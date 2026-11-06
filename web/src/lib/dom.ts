/**
 * Tiny DOM helpers. Everything is built with `createElement` + `textContent`
 * (never HTML strings), which keeps `require-trusted-types-for 'script'`
 * satisfied without a policy (the only policy, `dropr-sw`, is for the service
 * worker URL; see downloader.ts).
 *
 * @module
 */

import { errorMessage } from "./messages.ts";

/** Required element by id; a missing one is a template/contract bug (see docs/PAGES.md). */
export function byId<T extends HTMLElement = HTMLElement>(id: string, ctor?: abstract new () => T): T {
  const e = document.getElementById(id);
  if (e === null) throw new Error(`#${id} missing from the page (docs/PAGES.md)`);
  if (ctor !== undefined && !(e instanceof ctor)) throw new Error(`#${id} has the wrong element type`);
  return e as T;
}

/** Optional element by id. */
export function maybeId<T extends HTMLElement = HTMLElement>(id: string, ctor?: abstract new () => T): T | null {
  const e = document.getElementById(id);
  if (e === null || (ctor !== undefined && !(e instanceof ctor))) return null;
  return e as T;
}

type Child = Node | string | null | undefined | false;

export interface ElProps {
  readonly class?: string;
  readonly text?: string;
  readonly attrs?: Readonly<Record<string, string>>;
}

/** `createElement` with class, text and attributes. Children are nodes or plain text. */
export function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: ElProps = {}, ...children: Child[]): HTMLElementTagNameMap[K] {
  const e = document.createElement(tag);
  if (props.class !== undefined) e.className = props.class;
  if (props.text !== undefined) e.textContent = props.text;
  for (const [k, v] of Object.entries(props.attrs ?? {})) e.setAttribute(k, v);
  for (const c of children) if (c !== null && c !== undefined && c !== false) e.append(c);
  return e;
}

export function show(e: HTMLElement, visible = true): void {
  e.hidden = !visible;
}

/** Unhide elements rendered `hidden` with `data-js-only`; hide `data-nojs-only` ones. */
export function revealJsOnly(root: ParentNode = document): void {
  for (const e of root.querySelectorAll<HTMLElement>("[data-js-only]")) e.hidden = false;
  for (const e of root.querySelectorAll<HTMLElement>("[data-nojs-only]")) e.hidden = true;
}

/** The page's `<main data-page=…>` element, checked against the expected page name. */
export function pageRoot(name: string): HTMLElement | null {
  const main = document.querySelector<HTMLElement>("main[data-page]");
  return main !== null && main.dataset["page"] === name ? main : null;
}

/** Non-negative integer `data-*` value, or `fallback`. */
export function dataInt(e: HTMLElement, key: string, fallback: number): number {
  const v = e.dataset[key];
  if (v === undefined || !/^\d{1,16}$/.test(v)) return fallback;
  const n = Number(v);
  return Number.isSafeInteger(n) ? n : fallback;
}

/** Error area (role="alert") + optional status live region. */
export class Notice {
  private readonly errorEl: HTMLElement;
  private readonly statusEl: HTMLElement | null;

  constructor(errorEl: HTMLElement, statusEl: HTMLElement | null = null) {
    this.errorEl = errorEl;
    this.statusEl = statusEl;
  }

  /** Show an error (message from {@link errorMessage} if not a string) and move focus to it. */
  error(e: unknown, focus = true): void {
    this.errorEl.textContent = typeof e === "string" ? e : errorMessage(e);
    this.errorEl.hidden = false;
    if (!this.errorEl.hasAttribute("tabindex")) this.errorEl.tabIndex = -1;
    if (focus) this.errorEl.focus();
    if (typeof e !== "string" && !(e instanceof Error && e.name === "ApiError")) console.error(e);
  }

  clear(): void {
    this.errorEl.textContent = "";
    this.errorEl.hidden = true;
  }

  status(text: string): void {
    if (this.statusEl !== null) this.statusEl.textContent = text;
  }
}

/** Warn before leaving the page while `active()` is true. Returns a remover. */
export function warnBeforeUnload(active: () => boolean): () => void {
  const h = (ev: BeforeUnloadEvent): void => {
    if (!active()) return;
    ev.preventDefault();
    ev.returnValue = ""; // legacy browsers
  };
  window.addEventListener("beforeunload", h);
  return () => window.removeEventListener("beforeunload", h);
}

/**
 * Copy text with the Clipboard API; if that is unavailable or denied, select
 * the text in `input` so the user can press Ctrl/Cmd+C.
 */
export async function copyText(text: string, input?: HTMLInputElement): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    if (input !== undefined) {
      input.focus();
      input.select();
    }
    return false;
  }
}

/** Whether the user asked for reduced motion (used to skip smooth scrolling). */
export function prefersReducedMotion(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** Move focus to `e` (making it focusable if needed) and bring it into view. */
export function focusTo(e: HTMLElement): void {
  if (!e.hasAttribute("tabindex") && !(e instanceof HTMLButtonElement || e instanceof HTMLInputElement || e instanceof HTMLAnchorElement)) {
    e.tabIndex = -1;
  }
  e.focus({ preventScroll: true });
  e.scrollIntoView({ block: "nearest", behavior: prefersReducedMotion() ? "auto" : "smooth" });
}
