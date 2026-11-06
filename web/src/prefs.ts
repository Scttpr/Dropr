/**
 * Display settings (every page): language and color theme.
 *
 * The settings are a plain form in a native popover (layout.html), posted to
 * `/prefs` when scripts are off. Here the choice is applied in place instead:
 * the theme switches without a reload (with a cross-fade where the browser
 * supports view transitions), and a language change reloads the page, which
 * keeps the URL fragment, i.e. the key of a share or request link, that a
 * form post would lose.
 *
 * Both are kept in `__Host-` cookies so the server renders the next page in
 * the right language and theme, with no flash of the wrong one.
 *
 * Kept free of lib/ imports: it loads on every page, so it stays tiny.
 *
 * @module
 */

const LANG_COOKIE = "__Host-dropr_lang";
const THEME_COOKIE = "__Host-dropr_theme";
const MAX_AGE = 365 * 24 * 60 * 60;
const THEMES = ["light", "dark", "system"] as const;
type Theme = (typeof THEMES)[number];

const COLOR_SCHEME: Readonly<Record<Theme, string>> = { light: "light", dark: "dark", system: "light dark" };

function isTheme(v: string): v is Theme {
  return (THEMES as readonly string[]).includes(v);
}

function setCookie(name: string, value: string): void {
  document.cookie = `${name}=${value}; Path=/; Max-Age=${MAX_AGE}; Secure; SameSite=Lax`;
}

/** Mark `button` as the pressed one of its group. */
function press(button: HTMLButtonElement): void {
  for (const b of button.closest("fieldset")?.querySelectorAll("button") ?? []) {
    b.setAttribute("aria-pressed", String(b === button));
  }
}

function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  const swap = (): void => {
    root.dataset["theme"] = theme;
    document.querySelector('meta[name="color-scheme"]')?.setAttribute("content", COLOR_SCHEME[theme]);
  };
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (typeof document.startViewTransition === "function" && !still) document.startViewTransition(swap);
  else swap();
}

function init(form: HTMLFormElement): void {
  form.addEventListener("submit", (ev) => {
    const button = ev.submitter;
    if (!(button instanceof HTMLButtonElement)) return;
    const { name, value } = button;
    if (name === "theme" && isTheme(value)) {
      ev.preventDefault();
      setCookie(THEME_COOKIE, value);
      press(button);
      applyTheme(value);
    } else if (name === "lang" && /^[a-z]{2}$/.test(value)) {
      ev.preventDefault();
      if (button.getAttribute("aria-pressed") === "true") return;
      setCookie(LANG_COOKIE, value);
      location.reload();
    }
  });
}

const form = document.querySelector<HTMLFormElement>("form[data-prefs]");
if (form !== null) init(form);
