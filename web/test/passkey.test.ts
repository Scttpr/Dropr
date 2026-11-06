/**
 * WebAuthn JSON helpers (go-webauthn compatibility, PRF scrubbing) and the
 * passkey registration/unlock flows against fake authenticators and a fake
 * server, wired to the real crypto core.
 */

import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";
import { b64urlDecode, b64urlEncode, deriveKek, prfSalt, unwrapPrivateKey } from "../src/crypto/index.ts";
import { Api, ApiError } from "../src/lib/api.ts";
import {
  PRF_UNSUPPORTED_MESSAGE,
  PasskeyError,
  passkeyErrorMessage,
  PrfUnsupportedError,
  _resetKeyring,
  deletePasskey,
  ensureUnlocked,
  registerPasskey,
  unlock,
  unlockExtractable,
  unlockedKey,
  type CredentialsLike,
} from "../src/lib/passkey.ts";
import {
  type CredentialLike,
  b64uToBytes,
  creationOptionsFromJSON,
  credentialToJSON,
  decodeCreationOptions,
  decodeRequestOptions,
  choiceHints,
  hintsFromTransports,
  isAuthenticatorChoice,
  prfOutput,
  requestOptionsFromJSON,
} from "../src/lib/webauthn.ts";
import { fakeFetch, jsonResponse } from "./fakes.ts";

const enc = (s: string): string => b64urlEncode(new TextEncoder().encode(s));
const buf = (s: string): ArrayBuffer => new TextEncoder().encode(s).buffer as ArrayBuffer;
const USER_HANDLE = "user-handle-0123456789";

/** Shaped like go-webauthn's protocol.CredentialCreation JSON. */
const creationJSON = {
  publicKey: {
    rp: { name: "Dropr", id: "drop.example.com" },
    user: { name: "alice@example.com", displayName: "Alice", id: enc(USER_HANDLE) },
    challenge: enc("challenge-challenge-challenge-32"),
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ],
    timeout: 300000,
    excludeCredentials: [{ type: "public-key", id: enc("existing-cred"), transports: ["internal", "hybrid"] }],
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
    attestation: "none",
    extensions: { prf: { eval: { first: enc("server-chosen-salt") } } },
  },
};

/** Shaped like go-webauthn's protocol.CredentialAssertion JSON. */
const requestJSON = {
  publicKey: {
    challenge: enc("assertion-challenge-0123456789ab"),
    timeout: 300000,
    rpId: "drop.example.com",
    allowCredentials: [{ type: "public-key", id: enc("cred-1") }],
    userVerification: "required",
  },
};

describe("WebAuthn JSON", () => {
  it("decodes go-webauthn creation options (base64url → bytes)", () => {
    const o = decodeCreationOptions(creationJSON);
    assert.equal(o.rp.id, "drop.example.com");
    assert.equal(new TextDecoder().decode(o.user.id as Uint8Array), USER_HANDLE);
    assert.equal(new TextDecoder().decode(o.challenge as Uint8Array), "challenge-challenge-challenge-32");
    assert.deepEqual(o.pubKeyCredParams, [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ]);
    assert.equal(new TextDecoder().decode(o.excludeCredentials?.[0]?.id as Uint8Array), "existing-cred");
    assert.deepEqual(o.excludeCredentials?.[0]?.transports, ["internal", "hybrid"]);
    assert.equal(o.timeout, 300000);
  });

  it("leaves the authenticator to the browser by default and sets hints for an explicit choice", () => {
    const salt = prfSalt();
    const withServerHints = { ...creationJSON, hints: ["security-key"], authenticatorSelection: { authenticatorAttachment: "platform" } };
    const auto = creationOptionsFromJSON(withServerHints, salt) as PublicKeyCredentialCreationOptions & { hints?: string[] };
    assert.equal(auto.hints, undefined);
    assert.equal(auto.authenticatorSelection?.authenticatorAttachment, undefined);
    assert.equal(auto.authenticatorSelection?.residentKey, "required");
    for (const [choice, hint, attachment] of [
      ["device", "client-device", "platform"],
      ["phone", "hybrid", "cross-platform"],
      ["security-key", "security-key", "cross-platform"],
    ] as const) {
      const o = creationOptionsFromJSON(creationJSON, salt, choice) as PublicKeyCredentialCreationOptions & { hints?: string[] };
      assert.deepEqual(o.hints, [hint]);
      assert.equal(o.authenticatorSelection?.authenticatorAttachment, attachment);
      assert.equal(o.authenticatorSelection?.userVerification, "required");
    }
    assert.ok(isAuthenticatorChoice("phone") && isAuthenticatorChoice("auto"));
    assert.ok(!isAuthenticatorChoice("toString") && !isAuthenticatorChoice(undefined));
    assert.deepEqual(choiceHints("phone"), ["hybrid"]);
    assert.equal(choiceHints("auto"), undefined);
  });

  it("derives assertion hints from stored transports only when unambiguous", () => {
    assert.deepEqual(hintsFromTransports(["internal"]), ["client-device"]);
    assert.deepEqual(hintsFromTransports(["hybrid"]), ["hybrid"]);
    assert.deepEqual(hintsFromTransports(["usb", "nfc"]), ["security-key"]);
    assert.equal(hintsFromTransports(["hybrid", "internal"]), undefined);
    assert.equal(hintsFromTransports([]), undefined);
    assert.equal(hintsFromTransports(undefined), undefined);
    const salt = prfSalt();
    const withServerHints = { publicKey: { ...requestJSON.publicKey, hints: ["security-key"] } };
    assert.deepEqual((requestOptionsFromJSON(withServerHints, salt, ["hybrid"]) as { hints?: string[] }).hints, ["hybrid"]);
    assert.equal((requestOptionsFromJSON(requestJSON, salt) as { hints?: string[] }).hints, undefined);
  });

  it("forces resident key, UV and Dropr's PRF salt, ignoring the server's extensions", () => {
    const salt = prfSalt();
    const o = creationOptionsFromJSON(creationJSON, salt);
    assert.equal(o.authenticatorSelection?.residentKey, "required");
    assert.equal(o.authenticatorSelection?.userVerification, "required");
    assert.deepEqual(Object.keys(o.extensions ?? {}), ["prf"]);
    assert.equal(o.extensions?.prf?.eval?.first, salt);
    const r = requestOptionsFromJSON(requestJSON, salt);
    assert.equal(r.userVerification, "required");
    assert.equal(r.extensions?.prf?.eval?.first, salt);
    assert.equal(r.rpId, "drop.example.com");
  });

  it("decodes request options and accepts a bare object or padded base64url", () => {
    const r = decodeRequestOptions(requestJSON.publicKey);
    assert.equal(new TextDecoder().decode(r.allowCredentials?.[0]?.id as Uint8Array), "cred-1");
    assert.equal(new TextDecoder().decode(b64uToBytes("YWI=")), "ab");
    assert.throws(() => decodeRequestOptions({ nope: 1 }), TypeError);
  });

  it("serializes an attestation without PRF results (manual path)", () => {
    const cred: CredentialLike = {
      id: enc("cred-1"),
      rawId: buf("cred-1"),
      type: "public-key",
      authenticatorAttachment: "platform",
      response: { clientDataJSON: buf("cdj"), attestationObject: buf("att"), getTransports: () => ["internal"] },
      getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: new Uint8Array(32).fill(7) } }, credProps: { rk: true } }),
    };
    const j = credentialToJSON(cred);
    assert.deepEqual(j, {
      id: enc("cred-1"),
      rawId: enc("cred-1"),
      type: "public-key",
      response: { clientDataJSON: enc("cdj"), attestationObject: enc("att"), transports: ["internal"] },
      authenticatorAttachment: "platform",
      clientExtensionResults: { prf: { enabled: true }, credProps: { rk: true } },
    });
  });

  it("serializes an assertion (manual path) with userHandle", () => {
    const j = credentialToJSON({
      id: "x",
      rawId: buf("x"),
      type: "public-key",
      response: { clientDataJSON: buf("c"), authenticatorData: buf("a"), signature: buf("s"), userHandle: buf("u") },
      getClientExtensionResults: () => ({}),
    });
    assert.deepEqual(j["response"], { clientDataJSON: enc("c"), authenticatorData: enc("a"), signature: enc("s"), userHandle: enc("u") });
    assert.deepEqual(j["clientExtensionResults"], {});
  });

  it("scrubs prf.results from the browser's native toJSON()", () => {
    const secret = b64urlEncode(new Uint8Array(32).fill(9));
    const j = credentialToJSON({
      id: "x",
      rawId: buf("x"),
      type: "public-key",
      response: { clientDataJSON: buf("c"), authenticatorData: buf("a"), signature: buf("s") },
      getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(9) } } }),
      toJSON: () => ({
        id: "x",
        rawId: "eA",
        type: "public-key",
        response: { clientDataJSON: "Yw", authenticatorData: "YQ", signature: "cw" },
        clientExtensionResults: { prf: { results: { first: secret } } },
      }),
    });
    assert.ok(!JSON.stringify(j).includes(secret), "PRF output must never be sent");
    assert.deepEqual(j["clientExtensionResults"], {});
    assert.equal(j["rawId"], "eA");
  });

  it("extracts a 32-byte PRF output only", () => {
    assert.equal(prfOutput({}), null);
    assert.equal(prfOutput({ prf: { enabled: true } }), null);
    assert.equal(prfOutput({ prf: { results: { first: new Uint8Array(16) } } }), null);
    assert.equal(prfOutput({ prf: { results: { first: new Uint8Array(32).fill(1).buffer } } })?.length, 32);
  });
});

// ---------------------------------------------------------------------------
// Flows
// ---------------------------------------------------------------------------

/** A fake authenticator: one PRF secret per credential; PRF(salt) = SHA-256(secret ‖ salt). */
class FakeAuthenticator implements CredentialsLike {
  readonly creds = new Map<string, Uint8Array>();
  prfAtCreate: "results" | "enabled" | "none" = "enabled";
  creates: CredentialCreationOptions[] = [];
  gets: CredentialRequestOptions[] = [];
  private n = 0;

  private async prf(id: string, salt: BufferSource): Promise<ArrayBuffer> {
    const secret = this.creds.get(id) as Uint8Array;
    const s = new Uint8Array(salt instanceof ArrayBuffer ? salt : salt.buffer);
    const both = new Uint8Array(secret.length + s.length);
    both.set(secret);
    both.set(s, secret.length);
    return crypto.subtle.digest("SHA-256", both);
  }

  async create(o: CredentialCreationOptions): Promise<unknown> {
    this.creates.push(o);
    const id = `cred-${++this.n}`;
    this.creds.set(id, crypto.getRandomValues(new Uint8Array(32)));
    const salt = o.publicKey?.extensions?.prf?.eval?.first as BufferSource;
    const results = this.prfAtCreate === "results" ? { first: await this.prf(id, salt) } : undefined;
    const ext: AuthenticationExtensionsClientOutputs =
      this.prfAtCreate === "none" ? {} : { prf: results ? { enabled: true, results } : { enabled: true } };
    return {
      id: enc(id),
      rawId: buf(id),
      type: "public-key",
      response: { clientDataJSON: buf("cdj"), attestationObject: buf(`att-${id}`), getTransports: () => ["internal"] },
      getClientExtensionResults: () => ext,
    } satisfies CredentialLike;
  }

  async get(o: CredentialRequestOptions): Promise<unknown> {
    this.gets.push(o);
    const allowed = o.publicKey?.allowCredentials?.map((d) => new TextDecoder().decode(d.id as ArrayBuffer)) ?? [...this.creds.keys()];
    const id = allowed.find((a) => this.creds.has(a));
    if (id === undefined) throw new DOMException("no credential", "NotAllowedError");
    const salt = o.publicKey?.extensions?.prf?.eval?.first as BufferSource;
    const first = await this.prf(id, salt);
    return {
      id: enc(id),
      rawId: buf(id),
      type: "public-key",
      response: { clientDataJSON: buf("cdj"), authenticatorData: buf("ad"), signature: buf("sig"), userHandle: buf(USER_HANDLE) },
      getClientExtensionResults: () => ({ prf: { results: { first } } }),
    } satisfies CredentialLike;
  }
}

const CONFIRM_CHALLENGE = "confirm-challenge-0123456789abcd";

/**
 * Fake passkey endpoints storing wrapped keys per credential. Like the real
 * server, a registration on an account that already has a passkey needs the
 * "add" grant an assertion with that purpose leaves (single use); the first
 * registration (with or without the optional `confirm`) leaves one too.
 * Stored transports are `["internal"]`.
 */
function passkeyServer() {
  const wrapped = new Map<string, string>();
  const bodies: Record<string, unknown>[] = [];
  const purposes: unknown[] = [];
  const deleted: string[] = [];
  let pubkey: string | null = null;
  let lastUsed = "";
  let grant: unknown = null;
  let pendingPurpose: unknown = null;
  const f = fakeFetch((req) => {
    if (req.path === "/api/passkeys/register/begin") {
      if (wrapped.size > 0) {
        if ((grant as { purpose?: string } | null)?.purpose !== "add") return jsonResponse(403, { error: "reauth_required", message: "Confirm first." });
        grant = null;
      }
      return jsonResponse(200, { ...creationJSON, confirm: { challenge: enc(CONFIRM_CHALLENGE) } });
    }
    if (req.path === "/api/passkeys/register/finish") {
      const b = req.json as { credential: { id: string }; wrapped_privkey: string; pubkey: string; confirm?: unknown };
      bodies.push(b as unknown as Record<string, unknown>);
      if (pubkey !== null && pubkey !== b.pubkey) return jsonResponse(409, { error: "pubkey_mismatch" });
      if (wrapped.size === 0) grant = { purpose: "add" };
      pubkey = b.pubkey;
      wrapped.set(b.credential.id, b.wrapped_privkey);
      return jsonResponse(200, {});
    }
    if (req.path === "/api/passkeys/unlock/begin") {
      pendingPurpose = req.json;
      purposes.push(req.json);
      return jsonResponse(200, {
        publicKey: { ...requestJSON.publicKey, allowCredentials: [...wrapped.keys()].map((id) => ({ type: "public-key", id, transports: ["internal"] })) },
      });
    }
    if (req.path === "/api/passkeys/unlock/finish") {
      const b = req.json as { credential: { id: string } };
      bodies.push(b as unknown as Record<string, unknown>);
      lastUsed = b.credential.id;
      const w = wrapped.get(lastUsed);
      if (w === undefined) return jsonResponse(404, {});
      grant = pendingPurpose;
      return jsonResponse(200, { wrapped_privkey: w, credential_id: lastUsed });
    }
    if (req.method === "DELETE" && req.path.startsWith("/api/passkeys/")) {
      const id = req.path.slice("/api/passkeys/".length);
      const g = grant as { purpose?: string; passkey_id?: string } | null;
      grant = null;
      if (g?.purpose !== "delete" || g.passkey_id !== id) return jsonResponse(403, { error: "reauth_required", message: "Confirm first." });
      deleted.push(id);
      wrapped.delete(id);
      return new Response(null, { status: 204 });
    }
    return jsonResponse(404, {});
  });
  return { api: new Api({ fetch: f }), wrapped, bodies, purposes, deleted, pubkey: () => pubkey, clearGrant: () => void (grant = null) };
}

describe("passkey flows", () => {
  beforeEach(() => _resetKeyring());

  it("registers two passkeys wrapping the same key, never sending the PRF output", async () => {
    const auth = new FakeAuthenticator();
    const srv = passkeyServer();
    const deps = { api: srv.api, credentials: auth };

    let announced = 0;
    const k1 = await registerPasskey(null, deps, "auto", { onConfirmPrompt: () => void announced++ });
    // create() gave no PRF output: one get() restricted to the new
    // credential, announced beforehand, over the server's confirmation
    // challenge, which is sent back as "confirm".
    assert.equal(auth.gets.length, 1);
    assert.equal(announced, 1);
    const g = auth.gets[0]?.publicKey;
    // No choice ("auto"): hints from the credential's transports (["internal"]).
    assert.deepEqual((g as { hints?: string[] } | undefined)?.hints, ["client-device"]);
    assert.deepEqual(g?.allowCredentials?.[0]?.transports, ["internal"]);
    assert.equal(new TextDecoder().decode(g?.allowCredentials?.[0]?.id as ArrayBuffer), "cred-1");
    assert.equal(new TextDecoder().decode(g?.challenge as ArrayBuffer), CONFIRM_CHALLENGE);
    assert.equal(g?.userVerification, "required");
    assert.equal(g?.rpId, "drop.example.com");
    assert.deepEqual(new Uint8Array(g?.extensions?.prf?.eval?.first as ArrayBuffer), prfSalt());
    assert.equal(auth.creates[0]?.publicKey?.authenticatorSelection?.residentKey, "required");
    const confirm = srv.bodies[0]?.["confirm"] as Record<string, unknown> | undefined;
    assert.equal(confirm?.["id"], enc("cred-1"));
    assert.deepEqual(confirm?.["clientExtensionResults"], {}, "PRF output stripped from the confirmation");

    // The second passkey rides on the grant the first registration left.
    // Its PRF get() goes to the same place as the creation (the choice's hints).
    const k2 = await registerPasskey(k1, deps, "phone");
    assert.deepEqual((auth.creates[1]?.publicKey as { hints?: string[] } | undefined)?.hints, ["hybrid"]);
    assert.equal(auth.gets.length, 2);
    assert.deepEqual((auth.gets[1]?.publicKey as { hints?: string[] } | undefined)?.hints, ["hybrid"]);
    assert.equal(srv.wrapped.size, 2);
    assert.equal(b64urlEncode(k2.publicKey), srv.pubkey());

    for (const body of srv.bodies) {
      const cred = body["credential"] as Record<string, unknown>;
      assert.deepEqual(cred["clientExtensionResults"], { prf: { enabled: true } });
    }
    // Each wrapped blob opens with the KEK derived from that credential's PRF output and the user handle.
    for (const [credId, w] of srv.wrapped) {
      const id = new TextDecoder().decode(b64urlDecode(credId));
      const out = (await auth.get({ publicKey: { challenge: new Uint8Array(1), allowCredentials: [{ type: "public-key", id: buf(id) }], extensions: { prf: { eval: { first: prfSalt() } } } } })) as CredentialLike;
      const prf = prfOutput(out.getClientExtensionResults()) as Uint8Array;
      for (const body of srv.bodies) assert.ok(!JSON.stringify(body).includes(b64urlEncode(prf)), "PRF output leaked");
      const kek = await deriveKek(prf, new TextEncoder().encode(USER_HANDLE));
      const kp = await unwrapPrivateKey(kek, b64urlDecode(w));
      assert.equal(b64urlEncode(kp.publicKey), srv.pubkey());
    }
  });

  it("uses PRF results returned directly by create(): one prompt per passkey, no confirmation", async () => {
    const auth = new FakeAuthenticator();
    auth.prfAtCreate = "results";
    const srv = passkeyServer();
    let announced = 0;
    const k = await registerPasskey(null, { api: srv.api, credentials: auth }, "device", { onConfirmPrompt: () => void announced++ });
    assert.equal(auth.gets.length, 0, "no get() for the first passkey");
    assert.equal(announced, 0, "no second prompt announced");
    assert.equal(srv.bodies[0]?.["confirm"], undefined, "confirm is optional and omitted");
    // The first registration still leaves the grant for the second.
    await registerPasskey(k, { api: srv.api, credentials: auth });
    assert.equal(auth.gets.length, 0, "no get() for the second passkey");
    assert.equal(srv.bodies[1]?.["confirm"], undefined);
    assert.equal(srv.wrapped.size, 2);
    // Both wraps open with what a later unlock sees.
    for (const id of ["cred-1", "cred-2"]) {
      const w = srv.wrapped.get(enc(id)) as string;
      const out = (await auth.get({ publicKey: { challenge: new Uint8Array(1), allowCredentials: [{ type: "public-key", id: buf(id) }], extensions: { prf: { eval: { first: prfSalt() } } } } })) as CredentialLike;
      const kek = await deriveKek(prfOutput(out.getClientExtensionResults()) as Uint8Array, new TextEncoder().encode(USER_HANDLE));
      assert.equal(b64urlEncode((await unwrapPrivateKey(kek, b64urlDecode(w))).publicKey), srv.pubkey());
    }
  });

  it("confirming with the one existing passkey goes straight to where it lives", async () => {
    const auth = new FakeAuthenticator();
    auth.prfAtCreate = "results";
    const srv = passkeyServer();
    await registerPasskey(null, { api: srv.api, credentials: auth });
    srv.clearGrant(); // e.g. the 5 minutes passed
    // Default: from the single credential's stored transports (["internal"]).
    await unlockExtractable({ api: srv.api, credentials: auth });
    assert.deepEqual((auth.gets.at(-1)?.publicKey as { hints?: string[] } | undefined)?.hints, ["client-device"]);
    // Explicit hints (where the setup page saved it) win.
    await unlockExtractable({ api: srv.api, credentials: auth }, ["hybrid"]);
    assert.deepEqual((auth.gets.at(-1)?.publicKey as { hints?: string[] } | undefined)?.hints, ["hybrid"]);
    // Several passkeys: the browser decides.
    const k = await unlockExtractable({ api: srv.api, credentials: auth });
    await registerPasskey(k, { api: srv.api, credentials: auth });
    await unlock({ api: srv.api, credentials: auth });
    assert.equal((auth.gets.at(-1)?.publicKey as { hints?: string[] } | undefined)?.hints, undefined);
  });

  it("adding a passkey later confirms with an existing one first (purpose add)", async () => {
    const auth = new FakeAuthenticator();
    const srv = passkeyServer();
    const k = await registerPasskey(null, { api: srv.api, credentials: auth });
    await registerPasskey(k, { api: srv.api, credentials: auth });
    // Without a fresh assertion the server refuses.
    await assert.rejects(registerPasskey(k, { api: srv.api, credentials: auth }), (e: unknown) => e instanceof ApiError && e.code === "reauth_required");
    const ek = await unlockExtractable({ api: srv.api, credentials: auth });
    assert.deepEqual(srv.purposes.at(-1), { purpose: "add" });
    await registerPasskey(ek, { api: srv.api, credentials: auth });
    assert.equal(srv.wrapped.size, 3);
  });

  it("deletes a passkey after an assertion bound to that passkey", async () => {
    const auth = new FakeAuthenticator();
    const srv = passkeyServer();
    const k = await registerPasskey(null, { api: srv.api, credentials: auth });
    await registerPasskey(k, { api: srv.api, credentials: auth });
    const id = enc("cred-1");
    await deletePasskey(id, { api: srv.api, credentials: auth });
    assert.deepEqual(srv.purposes.at(-1), { purpose: "delete", passkey_id: id });
    assert.deepEqual(srv.deleted, [id]);
    // Plain unlocks carry no purpose.
    await unlock({ api: srv.api, credentials: auth });
    assert.deepEqual(srv.purposes.at(-1), { purpose: "unlock" });
  });

  it("refuses authenticators without PRF and asks the browser to forget the orphan credential", async () => {
    const auth = new FakeAuthenticator();
    auth.prfAtCreate = "none";
    const srv = passkeyServer();
    const signalled: string[] = [];
    await assert.rejects(
      registerPasskey(null, { api: srv.api, credentials: auth, signalUnknown: async (rp, id) => void signalled.push(`${rp}/${id}`) }),
      (e: unknown) => e instanceof PrfUnsupportedError && e.message === PRF_UNSUPPORTED_MESSAGE && /Microsoft Authenticator can't be used/.test(e.message),
    );
    assert.deepEqual(signalled, [`drop.example.com/${enc("cred-1")}`]);
    assert.equal(srv.wrapped.size, 0, "nothing registered");
  });

  it("maps a cancelled prompt to a plain-language PasskeyError", async () => {
    const srv = passkeyServer();
    const creds: CredentialsLike = {
      create: () => Promise.reject(new DOMException("x", "NotAllowedError")),
      get: () => Promise.reject(new DOMException("x", "NotAllowedError")),
    };
    await assert.rejects(
      registerPasskey(null, { api: srv.api, credentials: creds }),
      (e: unknown) => e instanceof PasskeyError && e.reason === "NotAllowedError" && /wasn't saved.*try again, or choose another place/.test(e.message),
    );
    await assert.rejects(
      unlock({ api: srv.api, credentials: creds }),
      (e: unknown) => e instanceof PasskeyError && /wasn't used.*Please try again/.test(e.message),
    );
  });

  it("every passkey error says what happened and what to do, without jargon", () => {
    for (const name of ["NotAllowedError", "InvalidStateError", "SecurityError", "NotSupportedError", "AbortError", "UnknownError"]) {
      for (const during of ["create", "get"] as const) {
        const m = passkeyErrorMessage(new DOMException("x", name), during);
        assert.match(m, /Please /, `${name}/${during}: says what to do`);
        assert.doesNotMatch(m, /PRF|WebAuthn|authenticator|hybrid|extension/i, `${name}/${during}: no jargon`);
      }
    }
    assert.match(passkeyErrorMessage(new DOMException("x", "InvalidStateError"), "create"), /already have a Dropr passkey there/);
    assert.doesNotMatch(PRF_UNSUPPORTED_MESSAGE, /PRF|WebAuthn|authenticator\b|hybrid/);
  });

  it("unlocks into a non-extractable in-memory key; ensureUnlocked prompts once", async () => {
    const auth = new FakeAuthenticator();
    const srv = passkeyServer();
    const k = await registerPasskey(null, { api: srv.api, credentials: auth });
    assert.equal(unlockedKey(), null);
    const gets = auth.gets.length;
    const [a, b] = await Promise.all([ensureUnlocked({ api: srv.api, credentials: auth }), ensureUnlocked({ api: srv.api, credentials: auth })]);
    assert.equal(a, b);
    assert.equal(auth.gets.length, gets + 1, "one prompt for concurrent callers");
    assert.equal(a.privateKey.extractable, false);
    assert.deepEqual(a.publicKey, k.publicKey);
    assert.equal(unlockedKey(), a);
    await ensureUnlocked({ api: srv.api, credentials: auth });
    assert.equal(auth.gets.length, gets + 1, "no prompt when already unlocked");
    const unlockBody = srv.bodies.at(-1) as Record<string, unknown>;
    assert.deepEqual((unlockBody["credential"] as Record<string, unknown>)["clientExtensionResults"], {});
  });

  it("unlocks extractable (for adding a passkey) without touching the keyring", async () => {
    const auth = new FakeAuthenticator();
    const srv = passkeyServer();
    await registerPasskey(null, { api: srv.api, credentials: auth });
    const k = await unlockExtractable({ api: srv.api, credentials: auth });
    assert.equal(k.privateKey.extractable, true);
    assert.equal(unlockedKey(), null);
    await registerPasskey(k, { api: srv.api, credentials: auth });
    assert.equal(srv.wrapped.size, 2);
  });

  it("reports a wrong passkey (blob does not open) clearly", async () => {
    const auth = new FakeAuthenticator();
    const srv = passkeyServer();
    await registerPasskey(null, { api: srv.api, credentials: auth });
    // Corrupt the stored blob.
    const [id, w] = [...srv.wrapped][0] as [string, string];
    const bytes = b64urlDecode(w);
    bytes[20] = (bytes[20] ?? 0) ^ 1;
    srv.wrapped.set(id, b64urlEncode(bytes));
    await assert.rejects(unlock({ api: srv.api, credentials: auth }), (e: unknown) => e instanceof PasskeyError && /could not unlock/.test(e.message));
    assert.equal(unlockedKey(), null);
  });
});
