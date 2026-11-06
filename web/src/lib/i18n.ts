/**
 * Interface language of the browser modules.
 *
 * The server negotiates the language (explicit choice cookie, then
 * Accept-Language) and writes it to `<html lang>`; the modules follow it, so
 * server-rendered and script-rendered text always agree. Outside a page (unit
 * tests in Node) the language is English.
 *
 * Catalogs are typed objects (`locales/en.ts` defines the shape): a missing
 * translation, or one with the wrong parameters, fails `tsc`. Messages with
 * values are functions, so plural rules and word order stay with each
 * language.
 *
 * @module
 */

import { en, type Messages } from "./locales/en.ts";
import { fr } from "./locales/fr.ts";

export type { Messages } from "./locales/en.ts";

export const LANGS = ["en", "fr"] as const;
export type Lang = (typeof LANGS)[number];

const CATALOGS: Readonly<Record<Lang, Messages>> = { en, fr };

/** A language and its catalog. Formatting helpers take one (default: the page's). */
export interface Locale {
  readonly lang: Lang;
  /** BCP 47 tag for `Intl` (dates, numbers): the visitor's regional variant of `lang` ("en-GB", "fr-CA") when they have one. */
  readonly tag: string;
  readonly t: Messages;
}

/** The supported language of a BCP 47 tag ("fr-CA" → "fr"), or English. */
export function parseLang(tag: string | null | undefined): Lang {
  const primary = (tag ?? "").trim().toLowerCase().split("-")[0];
  return (LANGS as readonly string[]).includes(primary ?? "") ? (primary as Lang) : "en";
}

export function localeFor(lang: Lang, preferred: readonly string[] = []): Locale {
  const tag = preferred.find((p) => p.toLowerCase().split("-")[0] === lang) ?? lang;
  return { lang, tag, t: CATALOGS[lang] };
}

/** The page's locale, from `<html lang>`. */
export const locale: Locale = globalThis.document === undefined
  ? localeFor("en")
  : localeFor(parseLang(document.documentElement.lang), navigator.languages);

/** The page's catalog. */
export const t: Messages = locale.t;
