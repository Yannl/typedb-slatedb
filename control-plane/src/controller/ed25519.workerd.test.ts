/*
 * R5-SEC-03 runtime support pin: WebCrypto Ed25519 under REAL workerd at
 * the pinned compatibility_date (2025-11-01, wrangler.local-dev.toml).
 *
 * This is the permanent form of the migration spike: if a workerd upgrade
 * or compat-date change ever regressed the Ed25519 surface the token layer
 * depends on (pkcs8 private import, raw public import, jwk public
 * derivation, sign/verify, generateKey), THIS fails first and names the
 * primitive, instead of every capability test failing opaquely.
 */
import { describe, expect, it } from "vitest";
import { ed25519PublicKeyFromPkcs8, ed25519Sign, ed25519Verify, generateEd25519KeyPair, pkcs8FromSeed } from "../shared/ed25519.ts";
import { hex, utf8 } from "../shared/journal-crypto.ts";
import { DEV_CAPABILITY_PUBLIC_KEY_HEX, devCapabilitySigningKey } from "../shared/key-config.ts";

describe("Ed25519 WebCrypto support (workerd, compat 2025-11-01)", () => {
  it("signs and verifies via pkcs8/raw imports; refuses tampering", async () => {
    const seed = new Uint8Array(32).fill(7);
    const priv = pkcs8FromSeed(seed);
    const pub = await ed25519PublicKeyFromPkcs8(priv);
    expect(pub.length).toBe(32);
    // the same seed-7 derivation as node produced (cross-runtime agreement)
    expect(hex(pub)).toBe("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c");
    const message = utf8("hello ed25519");
    const signature = await ed25519Sign(priv, message);
    expect(signature.length).toBe(64);
    expect(await ed25519Verify(pub, signature, message)).toBe(true);
    const tampered = Uint8Array.from(signature);
    tampered[0] ^= 1;
    expect(await ed25519Verify(pub, tampered, message)).toBe(false);
  });

  it("generates ephemeral keypairs and derives the committed dev public constant", async () => {
    const pair = await generateEd25519KeyPair();
    expect(pair.publicKey.length).toBe(32);
    expect(pair.privateKeyPkcs8.length).toBe(48);
    // the committed dev capability public key matches its committed seed
    // IN THIS RUNTIME too (no node-only derivation quirk)
    expect(hex(await ed25519PublicKeyFromPkcs8(devCapabilitySigningKey()))).toBe(DEV_CAPABILITY_PUBLIC_KEY_HEX);
  });
});
