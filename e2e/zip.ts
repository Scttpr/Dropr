/**
 * Minimal reader for the stored ZIP archives the dashboard builds (several
 * files in one share): end of central directory, central directory, local
 * headers. Enough to check what a recipient gets; ZIP64 is not needed for
 * test-sized archives and is refused.
 */

import { createHash } from "node:crypto";

export interface ZipMember {
  readonly name: string;
  readonly size: number;
  readonly sha256: string;
}

export function readStoredZip(buf: Buffer): ZipMember[] {
  const eocd = buf.length - 22;
  if (buf.readUInt32LE(eocd) !== 0x06054b50) throw new Error("no end of central directory (or an archive comment)");
  const count = buf.readUInt16LE(eocd + 10);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdOffset === 0xffffffff) throw new Error("ZIP64 archive: not expected in tests");
  const out: ZipMember[] = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error(`bad central header ${i}`);
    if ((buf.readUInt16LE(p + 8) & 0x0800) === 0) throw new Error("name not flagged UTF-8");
    if (buf.readUInt16LE(p + 10) !== 0) throw new Error("not stored");
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const offset = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString("utf8");
    if (buf.readUInt32LE(offset) !== 0x04034b50) throw new Error(`bad local header for ${name}`);
    const start = offset + 30 + buf.readUInt16LE(offset + 26) + buf.readUInt16LE(offset + 28);
    const data = buf.subarray(start, start + size);
    out.push({ name, size, sha256: createHash("sha256").update(data).digest("hex") });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}
