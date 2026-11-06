/** Request-link key store: records, owners, pruning, failures (over an in-memory backend). */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generateRequestKeyPair } from "../src/crypto/index.ts";
import { en } from "../src/lib/locales/en.ts";
import { errorMessage } from "../src/lib/messages.ts";
import { KeyStoreError, RequestKeyStore, requestPersistence } from "../src/lib/request-keys.ts";
import { memoryKeyBackend } from "./fakes.ts";

const NOW = 1_800_000_000;
const ALICE = "user-alice";
const BOB = "user-bob";

function storeFor(ownerId: string | null, backend = memoryKeyBackend()): { store: RequestKeyStore; backend: ReturnType<typeof memoryKeyBackend> } {
  return { store: new RequestKeyStore(ownerId, async () => backend), backend };
}

describe("request key store", () => {
  it("puts, gets, lists and deletes the owner's records", async () => {
    const { store, backend } = storeFor(ALICE);
    const a = await generateRequestKeyPair();
    await store.put("a", a, NOW);
    await store.put("b", await generateRequestKeyPair());
    assert.equal((backend.records.get("a") as { ownerId: string }).ownerId, ALICE);
    const got = await store.get("a");
    assert.equal(got?.privateKey, a.privateKey);
    assert.deepEqual(got?.publicKey, a.publicKey);
    assert.equal(got?.createdAt, NOW);
    assert.equal(await store.get("missing"), null);
    assert.deepEqual([...(await store.all()).keys()].sort(), ["a", "b"]);
    await store.delete("a");
    assert.equal(await store.get("a"), null);
    assert.deepEqual([...(await store.all()).keys()], ["b"]);
  });

  it("ignores malformed records", async () => {
    const { store, backend } = storeFor(ALICE);
    const kp = await generateRequestKeyPair();
    backend.records.set("x", { id: "x", ownerId: ALICE, privateKey: "not a key", publicKey: new Uint8Array(32), createdAt: 1 });
    backend.records.set("y", { id: "y", ownerId: ALICE, privateKey: kp.privateKey, publicKey: new Uint8Array(31), createdAt: 1 });
    assert.equal(await store.get("x"), null);
    assert.equal((await store.all()).size, 0);
  });

  it("prunes the owner's links the server no longer lists, keeping fresh records", async () => {
    const { store, backend } = storeFor(ALICE);
    for (const [id, at] of [["live", NOW - 3600], ["gone", NOW - 3600], ["fresh", NOW - 30], ["old", NOW - 61]] as const) {
      await store.put(id, await generateRequestKeyPair(), at);
    }
    const kept = await store.prune(["live", "unknown-here"], NOW);
    assert.deepEqual([...kept.keys()].sort(), ["fresh", "live"]);
    assert.deepEqual([...backend.records.keys()].sort(), ["fresh", "live"]);
  });

  it("keeps another account's records in a shared profile: invisible, never pruned or deleted", async () => {
    const backend = memoryKeyBackend();
    const alice = storeFor(ALICE, backend).store;
    const bob = storeFor(BOB, backend).store;
    await alice.put("a1", await generateRequestKeyPair(), NOW - 3600);
    await bob.put("b1", await generateRequestKeyPair(), NOW - 3600);
    // Bob opens /inbox: the server lists only his links.
    const kept = await bob.prune(["b1"], NOW);
    assert.deepEqual([...kept.keys()], ["b1"]);
    assert.deepEqual([...(await bob.all()).keys()], ["b1"]);
    assert.equal(await bob.get("a1"), null);
    await bob.delete("a1");
    await bob.prune([], NOW);
    assert.ok(backend.records.has("a1"), "Alice's key survives Bob's pruning and deletes");
    assert.ok((await alice.get("a1")) !== null);
    assert.deepEqual([...(await alice.all()).keys()], ["a1"]);
  });

  it("fails closed without an owner: no read, prune or put", async () => {
    const { store, backend } = storeFor(null);
    backend.records.set("a1", { id: "a1", ownerId: ALICE, ...(await generateRequestKeyPair()), createdAt: NOW - 3600 });
    const isOwnerUnknown = (e: unknown): boolean => e instanceof KeyStoreError && e.message === en.ownerUnknown;
    await assert.rejects(store.prune([], NOW), isOwnerUnknown);
    await assert.rejects(store.all(), isOwnerUnknown);
    await assert.rejects(store.put("x", await generateRequestKeyPair()), isOwnerUnknown);
    assert.deepEqual([...backend.records.keys()], ["a1"]);
  });

  it("reports an unavailable store with a plain-language KeyStoreError, and retries opening", async () => {
    let opens = 0;
    const backend = memoryKeyBackend();
    const store = new RequestKeyStore(ALICE, async () => {
      if (opens++ === 0) throw new DOMException("The operation is insecure.", "SecurityError");
      return backend;
    });
    await assert.rejects(store.all(), (e: unknown) => e instanceof KeyStoreError && e.message === en.keyStoreUnavailable);
    assert.equal((await store.all()).size, 0);
    assert.equal(opens, 2);
  });

  it("maps a full disk to the storage-full message and leaves nothing behind", async () => {
    const { store, backend } = storeFor(ALICE);
    backend.fail = new DOMException("full", "QuotaExceededError");
    const err = await store.put("a", await generateRequestKeyPair()).then(
      () => assert.fail("put should fail"),
      (e: unknown) => e,
    );
    assert.ok(err instanceof KeyStoreError);
    assert.equal(errorMessage(err), en.storageFull);
    assert.equal(backend.records.size, 0);
  });

  it("asks for persistent storage without ever throwing", async () => {
    assert.equal(await requestPersistence(), false); // Node: no navigator.storage
  });
});
