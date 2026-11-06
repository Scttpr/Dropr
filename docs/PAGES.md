# Dropr — Page ↔ JavaScript DOM contract

This document is the contract between the Go `html/template` pages
(`internal/web/templates`) and the browser modules (`web/src/*.ts`). A
template that follows it works with the JS without reading the JS. Element
ids, `data-*` names and element types below are **normative**: the JS looks
them up by id and throws (console) if a required one is missing.

Related: HTTP surface in `docs/ARCHITECTURE.md` §3, formats in `docs/FORMAT.md`.

## 1. Rules for every page

### 1.1 Script loading

- One page module per page (plus `prefs.js`, the display settings, on every
  page), in `<head>`, resolved through `manifest.json` (logical name → hashed
  file under `/assets/`):

  ```html
  <script type="module" src="/assets/{{asset "dashboard.js"}}"></script>
  ```

  Module scripts are deferred: the DOM is parsed when they run. No inline
  scripts, no inline event handlers, no `style` attributes (CSP).
- Server data reaches the JS **only through `data-*` attributes** on `<main>`
  (auto-escaped by `html/template`). Never JSON in a `<script>`.
- The page's root is `<main id="main" data-page="NAME" …>`. Each module only
  runs when `data-page` matches its name, so a template rendered with the
  wrong module does nothing.

| Page | Path | `data-page` | Manifest name |
|---|---|---|---|
| Dashboard | `/` (signed in) | `dashboard` | `dashboard.js` |
| Passkey setup | `/setup` | `setup` | `setup.js` |
| Received files | `/inbox` | `inbox` | `inbox.js` |
| Active links | `/links` | `links` | `links.js` |
| Share recipient | `/s/{id}` | `share` | `share.js` |
| Request uploader | `/r/{id}` | `request` | `request.js` |
| Service worker | `/sw.js` | – | `sw.js` (fixed name, see §9) |

The login page, error pages and the OIDC landing page load no page module
(only `prefs.js`).

### 1.2 Progressive enhancement

- Everything the JS needs that is useless without JS is rendered with both
  the `hidden` attribute **and** `data-js-only`. On start the module removes
  `hidden` from every `[data-js-only]` element.
- Elements carrying `data-nojs-only` are hidden by the JS (e.g. a plain-HTML
  explanation that is redundant once the JS runs).
- Each page has a `<noscript>` block (texts in each section below). All
  encryption happens in the browser, so the core actions need JavaScript;
  the pages must still render their headings, explanations and server-known
  facts (expiry, owner name, counts) as plain HTML.

### 1.3 Regions and accessibility

- **Status region**: `<p id="…-status" role="status" aria-live="polite"></p>`,
  rendered empty. The JS writes progress/state text into it (throttled).
- **Error region**: `<div id="…-error" role="alert" tabindex="-1" hidden></div>`,
  rendered empty and hidden. The JS fills it with a plain-language message
  (`textContent`) and moves focus to it.
- **Progress**: a real `<progress max="100" value="0">` element, labelled
  (`aria-labelledby` the file-name element or an `aria-label`).
- **Drop zones**: a container holding a visible `<label for=…>` and a native
  `<input type="file">`. Keyboard users use the input (Tab, then Enter/Space
  opens the picker); the JS adds drag-and-drop to the container and sets
  `data-dragover` on it while a file is dragged over (style hook), and
  `aria-disabled="true"` while busy. Do not make the container itself a
  button or give it `tabindex` (no nested interactive controls). The input may
  be visually styled but must stay focusable (no `display:none`).
- Buttons are `<button type="button">` unless stated otherwise.
- The JS moves focus to results (link field, error, "Sent" message) and back
  to a sensible control after deletions. It never animates; CSS should honour
  `prefers-reduced-motion` for any transitions it adds.
- JS-built content uses these class hooks: `danger` (destructive buttons),
  `qr` (the SVG), `name`/`size`/`date`/`expiry`/`downloads`/`files`/`actions`
  (table cells), `unreadable` (inbox name that failed to decrypt).

### 1.4 Values and units

- **Sizes** in `data-*` are integers in **bytes**. `data-max-file-size` and the
  request page's `data-max-bytes` are **plaintext** bytes (what the user picks);
  `data-max-request-bytes` is a **ciphertext** budget, passed through to the API. Every `size`
  exchanged with the JSON API is the **ciphertext** size (FORMAT.md §4.3).
- **Times** are Unix seconds.
- **Expiry choices** are exactly `1h`, `1d`, `7d`, `30d`.

### 1.5 Language and theme

- **Language.** The server picks it per request: the `__Host-dropr_lang`
  cookie (an explicit choice), else the best `Accept-Language` match, else
  English. It renders `<html lang="en|fr">` and `Content-Language`, and
  translates every server-rendered string (`internal/i18n`, msgid = the
  English text). The modules read `<html lang>` and take their text from the
  typed catalogs in `web/src/lib/locales/` (`en.ts` defines the shape; `tsc`
  rejects an incomplete one). API errors are translated in the browser from
  their `error` code; English shows the server's own `message`.
- Sentences are translated whole: never build one from fragments or
  substitute single words into markup (French articles agree in gender:
  "cet ordinateur", "cette tablette"). Plurals are handled by each catalog
  (`Intl.PluralRules`), lists by `Intl.ListFormat`, dates, numbers and
  percentages by `Intl` with the visitor's regional variant.
- **Theme.** `<html data-theme="light|dark|system">` from `__Host-dropr_theme`,
  **light by default**, with a matching `<meta name="color-scheme">`. CSS
  sets `color-scheme` from it and every color token is a `light-dark()`
  pair, so the page renders in its final colors on first paint.
- **Display settings** (every page, in the header): a button with
  `popovertarget="prefs"` opens a native popover holding a
  `<form method="post" action="/prefs" data-prefs>` with two groups of
  `type="submit"` buttons (`name="lang"`, `name="theme"`, the current one
  `aria-pressed="true"`). Without JavaScript the form posts and the server
  redirects back. `prefs.js` intercepts it instead: the theme switches in
  place, a language change sets the cookie and reloads, which keeps the URL
  fragment (the key of a share or request link).

## 2. Dashboard — `/`, `data-page="dashboard"`, `dashboard.js`

### `<main>` attributes

| Attribute | Required | Value |
|---|---|---|
| `data-max-file-size` | yes | instance `limits.max_file_size`, plaintext bytes (e.g. `5368709120`) |
| `data-default-expiry` | yes | `limits.default_expiry` (`7d` by default) |
| `data-max-request-bytes` | no | `max_bytes` sent when creating a request link: a **ciphertext** budget (the API counts ciphertext, §1.4). The server renders the ciphertext size of one maximal file, `CipherSize(max_file_size)`. If absent the JS falls back to `data-max-file-size`, which is slightly too small for a maximal file. |

### Share a file (flow A)

```html
<section aria-labelledby="share-heading">
  <h2 id="share-heading">Share a file</h2>
  <form id="share-form" data-js-only hidden>
    <div id="drop-zone" class="drop-zone">
      <label for="file-input">Drop a file here to share, or choose one</label>
      <input type="file" id="file-input" name="file">
    </div>
    <label for="expires-in">Link expires after</label>
    <select id="expires-in" name="expires_in">
      <option value="1h">1 hour</option>
      <option value="1d">1 day</option>
      <option value="7d" selected>7 days</option>   <!-- selected = data-default-expiry -->
      <option value="30d">30 days</option>
    </select>
    <label for="max-downloads">Download limit (optional)</label>
    <input type="number" id="max-downloads" name="max_downloads" min="1" max="999999" inputmode="numeric">
  </form>

  <div id="upload-panel" hidden>
    <p id="upload-file-name"></p>
    <progress id="upload-progress" max="100" value="0" aria-labelledby="upload-file-name"></progress>
    <p id="upload-status" role="status" aria-live="polite"></p>
    <button type="button" id="upload-cancel">Cancel</button>
    <button type="button" id="upload-retry" hidden>Retry</button>
  </div>

  <div id="share-result" hidden>
    <label for="share-link">Share link</label>
    <input type="text" id="share-link" readonly>
    <button type="button" id="share-copy">Copy</button>
    <p id="share-expiry"></p>
    <div id="share-qr"></div>
    <button type="button" id="share-another">Share another file</button>
  </div>

  <div id="share-error" role="alert" tabindex="-1" hidden></div>
</section>
```

Required ids: `share-form` (a `<form>`), `drop-zone`, `file-input`
(`<input type=file>`, **not** `multiple`), `upload-panel`, `upload-progress`
(`<progress>`), `upload-status`, `share-result`, `share-link` (`<input>`),
`share-copy` (`<button>`), `share-error`. Optional: `expires-in` (`<select>`;
default used if absent), `max-downloads`, `upload-file-name`, `upload-cancel`,
`upload-retry`, `share-expiry`, `share-qr`, `share-another`.

Behaviour: one file per share. While uploading, `share-form` is hidden and
`upload-panel` shown; Retry appears after a connection loss (the upload also
resumes by itself when the browser goes back online). On success
`share-result` is shown with the link `https://<host>/s/<id>#<key>`, the Copy
button, "Expires in N …" and an SVG QR code (`<svg class="qr" role="img">`);
focus moves to the link field. Cancelling or failing deletes the unfinished
share (`DELETE /api/shares/{id}`).

### Ask someone to send me a file (flow B)

```html
<section aria-labelledby="request-heading">
  <h2 id="request-heading">Receive a file</h2>
  <form id="request-form" data-js-only hidden>
    <label for="request-expires-in">Link expires after</label>
    <select id="request-expires-in">…same four options…</select>
    <label for="request-max-files">Maximum number of files</label>
    <input type="number" id="request-max-files" min="1" max="1000" value="10" inputmode="numeric">
    <label><input type="checkbox" id="request-single-use"> Single use</label>
    <button type="submit" id="request-create">Ask someone to send me a file</button>
  </form>
  <p id="request-status" role="status" aria-live="polite"></p>
  <div id="request-result" hidden>
    <label for="request-link">Request link</label>
    <input type="text" id="request-link" readonly>
    <button type="button" id="request-copy">Copy</button>
    <p id="request-expiry"></p>
    <div id="request-qr"></div>
  </div>
  <div id="request-error" role="alert" tabindex="-1" hidden></div>
</section>
```

Required (if `request-form` exists; the section is optional): `request-form`
(`<form>`), `request-error`, `request-result`, `request-link`, `request-copy`.
Optional: `request-expires-in`, `request-max-files` (default 10),
`request-single-use`, `request-create`, `request-status`, `request-expiry`,
`request-qr`.

Submitting prompts once for the passkey ("Unlock"), then shows
`https://<host>/r/<id>#<owner public key>`.

### Server-rendered navigation (plain HTML)

Links to `/inbox` ("Received files (3)") and `/links` ("Active links (2)")
with counts, and the sign-out form (`POST /auth/logout`). The counts are
wrapped in `<span id="inbox-count">` and `<span id="link-count">`: the JS adds
one to `link-count` after a share upload or a request link creation succeeds,
so the tile stays right without a reload. The inbox count (and its span) is
rendered only for a session that holds a passkey unlock ("Received files"
otherwise): someone signed in with only the owner's identity provider
credentials does not learn how many files arrived.

### noscript

> Dropr encrypts files in your browser before they are uploaded, so sharing
> and receiving files needs JavaScript. Please enable it for this site.

## 3. Passkey setup — `/setup`, `data-page="setup"`, `setup.js`

Audience: people who are not at ease with digital services. Plain, short
words; one obvious next action; no jargon (never "PRF", "WebAuthn",
"authenticator", "hybrid"); every error says what happened and what to do
next, with a way to try another option.

| Attribute | Required | Value |
|---|---|---|
| `data-passkey-count` | yes | number of passkeys the user already has (`0` or `1`) |
| `data-next` | no | same-origin path to go to when done (default `/`); anything else is ignored |

```html
<main id="main" data-page="setup" data-passkey-count="0" data-next="/">
  <h1>Protect your received files</h1>
  <p>A passkey is like a key that only you have, kept on your phone or computer.
     It keeps the files people send you private.</p>
  <p>You'll make two. The second one is a spare key, in case you lose the first.</p>
  <ol aria-label="Your progress">
    <li id="setup-step-1">Your first passkey</li>
    <li id="setup-step-2">Your spare passkey</li>
  </ol>
  <div id="setup-done" class="success" tabindex="-1" hidden>
    <p id="setup-done-title"></p><p id="setup-done-next"></p>
  </div>
  <h2 id="setup-step-title">Step 1 of 2: your first passkey</h2>
  <p id="setup-reauth" hidden>For your safety, first confirm with the passkey you already made. …</p>
  <fieldset id="setup-where" data-js-only hidden>
    <legend>Where do you want to keep this passkey?</legend>
    <div class="choice" id="setup-choice-device">
      <input type="radio" id="setup-where-device" name="setup-where" value="device"
             aria-describedby="setup-where-device-desc">
      <label for="setup-where-device"><span class="choice-title" id="setup-where-device-title">This computer</span>
        <span class="choice-badge" hidden>Recommended</span></label>
      <p id="setup-where-device-desc">…</p>
    </div>
    <!-- same for "phone" (+ title id setup-where-phone-title, desc, and the
         checklist <div id="setup-phone-help" hidden>), "security-key", and
         "auto" (checked by default; "Another way") -->
  </fieldset>
  <div id="setup-browser-note" hidden>
    <p>When you click the button, your browser will show you its own options. …</p>
    <p id="setup-browser-tip" hidden>…</p>
    <details id="setup-phone-tips" hidden><summary>Using your phone? What you need</summary></details>
  </div>
  <button type="button" id="setup-register" data-js-only hidden>Create my first passkey</button>
  <p id="setup-status" role="status" aria-live="polite"></p>
  <div id="setup-error" role="alert" tabindex="-1" hidden></div>
  <button type="button" id="setup-other" hidden>Try another way</button>
  <p>Without a passkey, files sent to you can't be opened. That's why the spare one matters.</p>
  <noscript>…</noscript>
</main>
```

Required: `setup-register` (`<button>`), `setup-status`, `setup-error`.
Optional (the JS skips what is missing): `setup-step-1`, `setup-step-2`
(the JS sets `data-state` = `done|current|todo` and `aria-current="step"`),
`setup-step-title`, `setup-done` (with `setup-done-title`,
`setup-done-next`), `setup-reauth`, `setup-browser-note` (with
`setup-browser-tip`, `setup-phone-tips`), `setup-other`, and `setup-where`.

**Where to save it.** `setup-where` holds one card `setup-choice-<value>`
per option, each with a radio `setup-where-<value>` named `setup-where`:
`device` (hint `client-device`, attachment `platform`), `phone` (`hybrid`,
`cross-platform`), `security-key` (`security-key`, `cross-platform`) and
`auto` (no hints: the browser or a password manager extension decides).
On a phone or tablet the JS rewrites the sentences that name the device
(`setup-where-device-title`, `setup-where-device-desc`,
`setup-where-phone-title`, `setup-where-phone-desc`,
`setup-phone-help-bluetooth`) as whole sentences, so translations can agree
in gender ("cet ordinateur", "ce téléphone", "cette tablette"). The JS (`lib/passkey-env.ts`) detects what can work with
`PublicKeyCredential.getClientCapabilities()` and
`isUserVerifyingPlatformAuthenticatorAvailable()`, then:

- hides an option known not to work (no passkey storage on this device; no
  phone support), keeps unknown ones without promising anything, and always
  keeps `security-key` and `auto`;
- moves the recommended option first, shows its `.choice-badge` and checks
  it: step 1 this device, else a phone; step 2 somewhere else than step 1
  (`device` is hidden in step 2 when step 1 used it; the place of step 1 is
  kept in `sessionStorage` `dropr:setup-last-choice` across a reload);
- shows `setup-phone-help` (Bluetooth on both devices, internet on both,
  Google Password Manager on Android and not Microsoft Authenticator,
  Passwords / iCloud Keychain on iPhone) while `phone` is checked;
- when the browser ignores hints (no `getClientCapabilities`, or Firefox),
  hides `setup-where` and shows `setup-browser-note` instead (choice
  `auto`), with `setup-browser-tip` when neither this device nor a phone
  can work and the phone checklist in `setup-phone-tips` on computers.

**Behaviour.** The button label per state: "Create my first passkey",
"Create my spare passkey", "Confirm with my first passkey" (step 2 that must
re-confirm), "Try again" (after an error). While a prompt is open,
`setup-status` says what to do there (e.g. "Scan the QR code with your
phone's camera, then follow the steps on your phone."). Step 1 creates the
passkey; if `create()` returned the PRF output that is the only prompt (no
`confirm` is sent). Otherwise one `get()` follows on the same credential
with the same hints and its transports, announced in `setup-status`
("Almost done. Your phone will ask you one more time to confirm. That's
normal."). After step 1, `setup-done` says "Your first passkey is ready."
and suggests a different device for the spare, and takes focus. The first
registration authorizes step 2 for 5 minutes, so step 2 normally prompts
only for the new passkey. With `data-passkey-count="1"` (page reloaded), or
when step 2 is answered `reauth_required`, `setup-reauth` explains why
before anything happens; the click then confirms with the existing passkey
(hinted to where step 1 saved it, or from its stored transports) and
creates the second. After the second, `setup-done` says "All done! Both of
your passkeys are ready." and the JS navigates to `data-next` 1.5 s later.

**Errors** go to `setup-error` (focused): plain sentences from
`lib/passkey.ts` (`passkeyErrorMessage`, `PRF_UNSUPPORTED_MESSAGE`, which
names the places that work and says Microsoft Authenticator can't be used).
A cancelled or timed-out phone attempt gets the phone checklist message.
`setup-other` ("Try another way") then appears; it checks the next offered
option and focuses it. Browsers without WebAuthn get a plain message and a
disabled button; browsers reporting no PRF support get a non-blocking one.

noscript:

> Setting up passkeys needs JavaScript. Please enable it for this site.

The server should redirect `/setup` → `/` once the user has ≥ 2 passkeys,
and `/`, `/inbox`, `/links` → `/setup` while they have fewer.

## 4. Received files — `/inbox`, `data-page="inbox"`, `inbox.js`

No `<main>` data is required (`data-count` may be rendered for CSS/text, only
for an unlocked session; the JS does not read it). The list is fetched from `GET /api/inbox` after unlock;
the server renders no rows.

```html
<main id="main" data-page="inbox">
  <h1>Received files</h1>
  <p id="inbox-warning" class="warning">These files were sent by people outside your
     organization through your request links. Only open files you expect.</p>
  <button type="button" id="inbox-unlock" data-js-only hidden>Unlock your inbox</button>
  <p id="inbox-status" role="status" aria-live="polite"></p>
  <div id="inbox-error" role="alert" tabindex="-1" hidden></div>

  <table id="inbox-table" hidden>
    <caption class="visually-hidden">Received files</caption>
    <thead><tr>
      <th scope="col">Name</th><th scope="col">Size</th><th scope="col">Received</th>
      <th scope="col"><span class="visually-hidden">Actions</span></th>
    </tr></thead>
    <tbody id="inbox-list"></tbody>
  </table>
  <p id="inbox-empty" hidden tabindex="-1">No files received yet.</p>

  <div id="download-panel" hidden>
    <p id="download-file-name"></p>
    <progress id="download-progress" max="100" value="0" aria-labelledby="download-file-name"></progress>
    <p id="download-status" role="status" aria-live="polite"></p>
    <button type="button" id="download-cancel">Cancel</button>
  </div>
  <noscript>…</noscript>
</main>
```

Required: `inbox-unlock` (`<button>`), `inbox-status`, `inbox-error`,
`inbox-table`, `inbox-list` (`<tbody>`), `inbox-empty`, `download-panel`,
`download-progress` (`<progress>`), `download-status`. Optional:
`download-file-name`, `download-cancel`, `inbox-warning`.

Rows built by the JS (4 cells, matching the header):
`<tr data-inbox-id="…"><td class="name">…</td><td class="size">…</td><td class="date"><time datetime="…">…</time></td><td class="actions"><button>Download</button> <button class="danger">Delete</button></td></tr>`.
Entries that fail to decrypt show "Unreadable file" (`class="name unreadable"`)
with Delete only. Delete asks for confirmation (`confirm()`).

The unlocked key lives in the page's memory only: every visit to `/inbox`
asks for the passkey once.

noscript:

> Received files are decrypted in your browser with your passkey, which needs
> JavaScript. Please enable it for this site.

## 5. Active links — `/links`, `data-page="links"`, `links.js`

Both lists are fetched from `GET /api/shares` and `GET /api/requests`.

```html
<main id="main" data-page="links">
  <h1>Active links</h1>
  <p id="links-status" role="status" aria-live="polite"></p>
  <div id="links-error" role="alert" tabindex="-1" hidden></div>

  <section aria-labelledby="shares-heading">
    <h2 id="shares-heading">Share links</h2>
    <table id="shares-table" hidden>
      <thead><tr><th scope="col">Size</th><th scope="col">Created</th><th scope="col">Expires</th>
        <th scope="col">Downloads</th><th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
      <tbody id="shares-list"></tbody>
    </table>
    <p id="shares-empty" hidden tabindex="-1">No active share links.</p>
  </section>

  <section aria-labelledby="requests-heading">
    <h2 id="requests-heading">Request links</h2>
    <table id="requests-table" hidden>
      <thead><tr><th scope="col">Created</th><th scope="col">Expires</th><th scope="col">Files received</th>
        <th scope="col"><span class="visually-hidden">Actions</span></th></tr></thead>
      <tbody id="requests-list"></tbody>
    </table>
    <p id="requests-empty" hidden tabindex="-1">No active request links.</p>
  </section>
  <noscript>…</noscript>
</main>
```

All ids above are required (`*-list` are `<tbody>`). Share rows: size,
created, "Expires in …", "2 of 5" / "2", **Revoke**. Request rows: created,
expiry, "1 of 10 (single use)", **Copy link** (asks for the passkey: the link
fragment is the owner's public key, taken only from the unlocked key) and
**Revoke**. Share names are not shown (see §10).

noscript:

> Managing links needs JavaScript. Please enable it for this site.

## 6. Share recipient — `/s/{id}`, `data-page="share"`, `share.js`

| Attribute | Required | Value |
|---|---|---|
| `data-share-id` | yes | the 22-char share id from the path |
| `data-expires-at` | yes | share expiry, Unix seconds (the JS writes "Expires in N days"; server and JS both round up to the largest unit that fits, so a fresh 7-day link reads "7 days") |

```html
<main id="main" data-page="share" data-share-id="…" data-expires-at="1767225600">
  <h1 id="file-name">Someone shared a file with you</h1>
  <p id="file-size"></p>
  <p id="file-expiry">Expires in 7 days</p>          <!-- server-rendered text, refreshed by JS -->
  <button type="button" id="download-button" data-js-only hidden>Download</button>
  <div id="download-panel" hidden>
    <progress id="download-progress" max="100" value="0" aria-label="Download progress"></progress>
    <p id="download-status" role="status" aria-live="polite"></p>
    <button type="button" id="download-cancel">Cancel</button>
  </div>
  <div id="download-error" role="alert" tabindex="-1" hidden></div>
  <p class="hint">The file is decrypted in your browser. The server never sees its contents or name.</p>
  <noscript>…</noscript>
</main>
```

Required: `file-name`, `download-button` (`<button>`), `download-panel`,
`download-progress` (`<progress>`), `download-status`, `download-error`.
Optional: `file-size`, `file-expiry`, `download-cancel`.

Behaviour: the key is in the URL fragment (never sent to the server). On
load the JS calls `POST /api/s/{id}/download` (does not count as a
download), decrypts the name into `#file-name` (`textContent`), the size into
`#file-size`, sets `document.title`, then enables the button. Plain-language
errors: missing key ("This link is missing its key…"), wrong key / damaged,
expired, download limit reached, revoked/unknown. Download goes, in order of
preference, to a save dialog (File System Access), the browser's download
manager (service worker) or, for files ≤ 256 MiB only, memory (with a
notice).

**Dead links**: when the server already knows the link is unknown, revoked,
expired or exhausted, it should render that state itself (HTTP 404/410,
plain sentence such as "This link has expired.") and **omit the script and
`data-share-id`**.

noscript:

> This file is end-to-end encrypted and is decrypted in your browser, which
> needs JavaScript. Please enable it for this site to download the file.

## 7. Request uploader — `/r/{id}`, `data-page="request"`, `request.js`

| Attribute | Required | Value |
|---|---|---|
| `data-request-id` | yes | the 22-char request id from the path |
| `data-max-files` | no | files this link still accepts (`max_files − files_received`) |
| `data-max-bytes` | no | plaintext bytes it still accepts (`max_bytes − bytes_received`) |

The limits only give early, friendly errors; the server enforces them.

```html
<main id="main" data-page="request" data-request-id="…" data-max-files="10" data-max-bytes="5368709120">
  <h1 id="request-title">Send a file to Alice</h1>   <!-- display name, server-rendered -->
  <p>Files are encrypted in your browser. Only Alice can open them.</p>
  <div id="drop-zone" class="drop-zone" data-js-only hidden>
    <label for="file-input">Drop files here, or choose them</label>
    <input type="file" id="file-input" name="files" multiple>
  </div>
  <div id="upload-panel" hidden>
    <p id="upload-file-name"></p>
    <progress id="upload-progress" max="100" value="0" aria-labelledby="upload-file-name"></progress>
    <p id="upload-status" role="status" aria-live="polite"></p>
    <button type="button" id="upload-cancel">Cancel</button>
    <button type="button" id="upload-retry" hidden>Retry</button>
  </div>
  <ul id="upload-list"></ul>
  <p id="upload-done" hidden tabindex="-1">✓ Sent. You can close this page.</p>
  <div id="upload-error" role="alert" tabindex="-1" hidden></div>
  <noscript>…</noscript>
</main>
```

Required: `drop-zone`, `file-input` (`<input type=file multiple>`),
`upload-panel`, `upload-progress` (`<progress>`), `upload-status`,
`upload-done`, `upload-error`. Optional: `upload-file-name`, `upload-cancel`,
`upload-retry`, `upload-list` (gets one `<li>` per sent file).

Behaviour: the owner's public key is in the URL fragment; without a valid
fragment the drop zone is hidden and "This link is incomplete or damaged…"
is shown. Files are sent one after the other; then `#upload-done` is shown
and focused. Dead links: render the state server-side as for `/s/{id}`.

noscript:

> Files are encrypted in your browser before they are sent, which needs
> JavaScript. Please enable it for this site.

## 8. JSON shapes the pages rely on

In addition to ARCHITECTURE.md §3 (all `size` values are ciphertext bytes,
times Unix seconds, binary values unpadded base64url):

- `GET /api/shares` → array (or `{"shares": [...]}`) of
  `{id, size, expires_at, max_downloads: int|null, download_count, created_at}`.
- `GET /api/requests` → array (or `{"requests": [...]}`) of
  `{id, expires_at, max_files, max_bytes, single_use: bool, files_received, bytes_received, created_at}`.
- `GET /api/inbox` → array (or `{"inbox": [...]}`) of
  `{id, request_id, size, created_at, meta, wrapped_key}`.
- `GET /api/passkeys` → array (or `{"passkeys": [...]}`) of `{id, created_at, last_used_at: int|null}`.
- `POST /api/passkeys/unlock/finish` → `{wrapped_privkey, credential_id, user_handle?}`
  (`user_handle` optional fallback for authenticators that omit it).
- `POST /api/passkeys/register/begin` → `{publicKey: {...}, confirm: {challenge}}`;
  `POST /api/passkeys/unlock/begin` takes `{purpose?: "unlock"|"add"|"delete", passkey_id?}`
  (ARCHITECTURE.md §3 "Passkeys": adding or deleting a passkey needs a fresh
  assertion made for that action; 403 `reauth_required` otherwise).
- `GET /upload/{id}` is called with the `Authorization: Bearer` upload token.
- `GET /dl/{token}` with `Range: bytes=N-` must answer `206` with
  `Content-Range: bytes N-(size-1)/size`; without Range, `200`. Anything else
  is treated as a broken server.
- Errors: `{"error": code, "message": text}`. Codes the pages recognise:
  `expired`, `exhausted`, `token_used` (download token byte budget spent: the
  downloader fetches a new token), `revoked`, `locked` (session not unlocked),
  `reauth_required` (fresh passkey assertion needed),
  `quota_exceeded`, `too_large`. `message` is shown verbatim (as text) when
  present and ≤ 300 characters.

## 9. Service worker (`/sw.js`)

- Built as a classic script (IIFE) with a fixed file name, `sw.js`, listed in
  the manifest as `"sw.js": "sw.js"`. Serve it at `/sw.js` with
  `Content-Type: text/javascript` and `Cache-Control: no-cache`.
- The pages register it with **scope `/_dl/`**, so it controls nothing but
  one-shot download URLs `/_dl/<22-char id>`; every other request bypasses
  it by construction. It caches nothing.
- The server must never serve content under `/_dl/`: a request reaching the
  server there means the worker was not active; answer 404 with a short page
  ("The download could not start. Go back and try again."). These URLs carry
  no secrets (random id only; the file name is not in the URL).
- The streamed response carries `Content-Type: application/octet-stream`,
  `Content-Disposition: attachment; filename="…"; filename*=UTF-8''…`,
  `Content-Security-Policy: default-src 'none'; sandbox`,
  `X-Content-Type-Options: nosniff`, `Content-Length`.
- Limitation: if decryption or the network fails mid-way, the browser shows a
  failed download (it cannot be told why); the page shows the reason.

## 10. Headers the pages need

- `Permissions-Policy` must keep `publickey-credentials-create=(self)`,
  `publickey-credentials-get=(self)` and `clipboard-write=(self)` allowed;
  a blanket "deny all" breaks setup, unlock and Copy.
- CSP as in ARCHITECTURE.md §7 works unchanged (`trusted-types dropr-sw` allows the
  one policy that registers the service worker; `worker-src 'self'` is
  needed for the service worker; the QR code is inline SVG built with DOM
  APIs, not an image).

### Why share names are not on `/links`

A share's name is sealed under its FK, which only the link holds; the
owner's browser does not keep it. A possible extension (not implemented):
the dashboard HPKE-seals FK to the owner's own public key
(`info = "dropr/v1 share " ‖ shareId`) and stores it as `owner_key` with
`PUT /api/shares/{id}/owner_key` before finalizing (the id is only known
after `POST /api/shares`). After unlocking, `/links` could then show names
and rebuild share links. It needs the authenticated public key at share
time, i.e. a passkey unlock for flow A, which today needs OIDC only.
