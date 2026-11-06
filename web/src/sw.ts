/**
 * Download service worker, served at `/sw.js` and registered with scope
 * `/_dl/` (see `lib/swproto.ts` for the protocol).
 *
 * It does exactly one thing: answer a navigation to `/_dl/<id>` that a page
 * registered moments before with a streamed `attachment` response whose body
 * is the decrypted file. It caches nothing and never touches any other
 * request (the scope keeps other pages out of its reach, and unknown ids fall
 * through to the network).
 *
 * Built as a classic script (IIFE), not a module worker, for the widest
 * support; it has no imports at run time.
 *
 * Limitation: once the response has started, an error (network failure,
 * failed authentication) can only *error the stream*. The browser then marks
 * the download as failed ("Network error") and discards it; it cannot be
 * told why. The page shows the reason.
 *
 * @module
 */

import { REGISTRATION_TTL_MS, downloadHeaders, downloadIdFromPath, parseRegister } from "./lib/swproto.ts";
import type { PortToSw, SwToPage } from "./lib/swproto.ts";

const sw = self as unknown as ServiceWorkerGlobalScope;

interface Pending {
  readonly name: string;
  readonly size: number | null;
  readonly stream: ReadableStream<Uint8Array>;
  readonly timer: ReturnType<typeof setTimeout>;
}

const pending = new Map<string, Pending>();

sw.addEventListener("install", () => {
  void sw.skipWaiting();
});

sw.addEventListener("activate", (event) => {
  event.waitUntil(sw.clients.claim());
});

/** Body fed over a MessagePort with one `pull` per chunk (browsers without transferable streams). */
function portStream(port: MessagePort): ReadableStream<Uint8Array> {
  let answer: (() => void) | null = null;
  let finished = false;
  const settle = (): void => {
    const a = answer;
    answer = null;
    a?.();
  };
  return new ReadableStream<Uint8Array>(
    {
      start(controller) {
        port.onmessage = (ev: MessageEvent<PortToSw>) => {
          const msg = ev.data;
          if (finished) return;
          if (msg.type === "chunk" && msg.chunk instanceof ArrayBuffer) {
            controller.enqueue(new Uint8Array(msg.chunk));
          } else if (msg.type === "end") {
            finished = true;
            controller.close();
            port.close();
          } else {
            finished = true;
            controller.error(new Error("download aborted"));
            port.close();
          }
          settle();
        };
      },
      pull() {
        if (finished) return;
        return new Promise<void>((resolve) => {
          answer = resolve;
          port.postMessage({ type: "pull" } satisfies SwToPage);
        });
      },
      cancel() {
        // The user cancelled the download in the browser UI.
        finished = true;
        port.postMessage({ type: "cancel" } satisfies SwToPage);
        port.close();
        settle();
      },
    },
    { highWaterMark: 0 },
  );
}

sw.addEventListener("message", (event: ExtendableMessageEvent) => {
  // Only same-origin window clients can reach us; check anyway.
  if (event.origin !== "" && event.origin !== sw.location.origin) return;
  const reg = parseRegister(event.data);
  const port = event.ports[0];
  if (reg === null || port === undefined) return; // keepalive or junk: receiving it extends our lifetime
  pending.get(reg.id)?.stream.cancel().catch(() => undefined);
  const stream = reg.stream ?? portStream(port);
  const timer = setTimeout(() => {
    const p = pending.get(reg.id);
    if (p === undefined) return;
    pending.delete(reg.id);
    p.stream.cancel().catch(() => undefined);
  }, REGISTRATION_TTL_MS);
  pending.set(reg.id, { name: reg.name, size: reg.size, stream, timer });
  port.postMessage({ type: "registered" } satisfies SwToPage);
});

sw.addEventListener("fetch", (event: FetchEvent) => {
  const url = new URL(event.request.url);
  if (url.origin !== sw.location.origin || event.request.method !== "GET") return;
  const id = downloadIdFromPath(url.pathname);
  if (id === null) return;
  const p = pending.get(id);
  if (p === undefined) return; // unknown or already used: let the network answer (404)
  pending.delete(id);
  clearTimeout(p.timer);
  event.respondWith(new Response(p.stream, { status: 200, headers: downloadHeaders(p.name, p.size) }));
});
