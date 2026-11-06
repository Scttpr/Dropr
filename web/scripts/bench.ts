/**
 * Throughput of the STREAM implementation on 256 MiB in Node (WebCrypto).
 * Usage: npm run bench [-- --mib 256]
 */

import { parseArgs } from "node:util";
import { deriveFileKeys, generateFileKey } from "../src/crypto/filekey.ts";
import {
  ciphertextSize,
  createDecryptStream,
  createEncryptStream,
  encryptPart,
  partCount,
  partPlainRange,
} from "../src/crypto/stream.ts";

const { values } = parseArgs({ options: { mib: { type: "string", default: "256" } } });
const MiB = 1 << 20;
const size = Number(values.mib) * MiB;
const CHUNK = MiB;

const pt = new Uint8Array(size);
for (let off = 0; off < size; off += 65_536) crypto.getRandomValues(pt.subarray(off, Math.min(off + 65_536, size)));
const { content: ck } = await deriveFileKeys(generateFileKey());

async function time(label: string, bytes: number, fn: () => Promise<void>): Promise<void> {
  await fn(); // warm-up: JIT, first-touch page faults
  const t0 = performance.now();
  await fn();
  const s = (performance.now() - t0) / 1000;
  console.log(`${label.padEnd(28)} ${(bytes / MiB / s).toFixed(0).padStart(6)} MiB/s  (${s.toFixed(2)} s)`);
}

function source(data: Uint8Array, chunk: number): ReadableStream<Uint8Array> {
  let off = 0;
  return new ReadableStream({
    pull(c) {
      if (off >= data.length) return c.close();
      c.enqueue(data.subarray(off, off + chunk));
      off += chunk;
    },
  });
}

console.log(`node ${process.version}, ${size / MiB} MiB plaintext`);

const c = ciphertextSize(size);
const ct = new Uint8Array(c);
await time("encryptPart (32 MiB parts)", size, async () => {
  const n = partCount(c);
  for (let i = 0; i < n; i++) {
    const r = partPlainRange(i, size);
    ct.set(await encryptPart(ck, i, pt.subarray(r.start, r.end), i === n - 1), i * 33_562_624);
  }
});

await time("createEncryptStream", size, async () => {
  const reader = source(pt, CHUNK).pipeThrough(createEncryptStream(ck)).getReader();
  let n = 0;
  for (let r = await reader.read(); !r.done; r = await reader.read()) n += r.value.length;
  if (n !== c) throw new Error("size mismatch");
});

await time("createDecryptStream", size, async () => {
  const reader = source(ct, CHUNK).pipeThrough(createDecryptStream(ck)).getReader();
  let n = 0;
  for (let r = await reader.read(); !r.done; r = await reader.read()) n += r.value.length;
  if (n !== size) throw new Error("size mismatch");
});
