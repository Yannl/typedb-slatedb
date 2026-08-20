#!/usr/bin/env node
// Independent Ed25519 implementation for release-root signatures.
//
// This shares NO code with tools/release/ed25519_ref.py — it is Node's
// `crypto` (OpenSSL) reached through raw SPKI/PKCS#8 wrappers. release.py
// verifies every signature with BOTH implementations and fails closed when
// they disagree, so a defect in the pure-Python signer cannot vouch for
// itself.
//
// usage:
//   ed25519_node.mjs verify <publicKeyHex32> <messageHex> <signatureHex64>
//       -> VERIFIED | NOT_VERIFIED | MALFORMED <reason>
//   ed25519_node.mjs sign <seedHex32> <messageHex>   -> <signatureHex64>
//   ed25519_node.mjs pub  <seedHex32>                -> <publicKeyHex32>

import {
  createPublicKey, createPrivateKey, verify as cryptoVerify, sign as cryptoSign,
} from "node:crypto";

// RFC 8410 §4 SubjectPublicKeyInfo / §7 PrivateKeyInfo DER prefixes for the
// Ed25519 OID 1.3.101.112, wrapping the raw 32-byte key material.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function fail(reason) {
  process.stdout.write(`MALFORMED ${reason}\n`);
  process.exit(2);
}

function hexBytes(s, n, label) {
  if (typeof s !== "string" || !/^[0-9a-f]*$/.test(s) || s.length % 2 !== 0) {
    fail(`${label}-not-lowercase-hex`);
  }
  const b = Buffer.from(s, "hex");
  if (n !== null && b.length !== n) fail(`${label}-length-${b.length}-want-${n}`);
  return b;
}

function publicKeyObject(pub) {
  try {
    return createPublicKey({
      key: Buffer.concat([SPKI_PREFIX, pub]), format: "der", type: "spki",
    });
  } catch (err) {
    return fail(`public-key-rejected:${err.code ?? err.message}`);
  }
}

function privateKeyObject(seed) {
  try {
    return createPrivateKey({
      key: Buffer.concat([PKCS8_PREFIX, seed]), format: "der", type: "pkcs8",
    });
  } catch (err) {
    return fail(`seed-rejected:${err.code ?? err.message}`);
  }
}

const [cmd, ...rest] = process.argv.slice(2);

if (cmd === "verify") {
  const [pubHex, msgHex, sigHex] = rest;
  if (pubHex === undefined || msgHex === undefined || sigHex === undefined) {
    fail("usage: verify <publicKeyHex> <messageHex> <signatureHex>");
  }
  const key = publicKeyObject(hexBytes(pubHex, 32, "public-key"));
  const msg = hexBytes(msgHex, null, "message");
  const sig = hexBytes(sigHex, 64, "signature");
  let ok = false;
  try {
    ok = cryptoVerify(null, msg, key, sig);
  } catch (err) {
    fail(`verify-threw:${err.code ?? err.message}`);
  }
  process.stdout.write(ok ? "VERIFIED\n" : "NOT_VERIFIED\n");
  process.exit(ok ? 0 : 1);
} else if (cmd === "sign") {
  const [seedHex, msgHex] = rest;
  if (seedHex === undefined || msgHex === undefined) {
    fail("usage: sign <seedHex> <messageHex>");
  }
  const key = privateKeyObject(hexBytes(seedHex, 32, "seed"));
  const sig = cryptoSign(null, hexBytes(msgHex, null, "message"), key);
  process.stdout.write(`${sig.toString("hex")}\n`);
} else if (cmd === "pub") {
  const [seedHex] = rest;
  if (seedHex === undefined) fail("usage: pub <seedHex>");
  const key = createPublicKey(privateKeyObject(hexBytes(seedHex, 32, "seed")));
  const der = key.export({ format: "der", type: "spki" });
  process.stdout.write(`${der.subarray(SPKI_PREFIX.length).toString("hex")}\n`);
} else {
  fail(`unknown-subcommand:${cmd ?? "(none)"}`);
}
