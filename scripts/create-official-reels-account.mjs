import { webcrypto } from "node:crypto";
import WebSocket from "ws";

globalThis.crypto ||= webcrypto;

const peerId = String(process.env.OFFICIAL_REELS_PEER_ID || "701337");
const password = String(process.env.OFFICIAL_REELS_PASSWORD || "");
const recoveryPhrase = String(process.env.OFFICIAL_REELS_RECOVERY || "");
if (!/^\d{6}$/.test(peerId) || password.length < 12 || recoveryPhrase.split(/\s+/).length < 8) {
  throw new Error("Official Reels credentials are incomplete.");
}

const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
const identity = {
  id: peerId,
  publicKeyJwk: await crypto.subtle.exportKey("jwk", pair.publicKey),
  privateKeyJwk: await crypto.subtle.exportKey("jwk", pair.privateKey),
  createdAt: new Date().toISOString()
};
const encryptedIdentityBackup = await encryptBackup(identity, password);
const encryptedRecoveryBackup = await encryptBackup(identity, recoveryPhrase);
const ws = new WebSocket("wss://bypassium-signaling-server.onrender.com");
await onceOpen(ws);
ws.send(JSON.stringify({ type: "register", peerId, publicKeyJwk: identity.publicKeyJwk }));
await onceMessage(ws, "registered");
const requestId = crypto.randomUUID();
ws.send(JSON.stringify({
  type: "create-account",
  requestId,
  peerId,
  password,
  publicKeyJwk: identity.publicKeyJwk,
  encryptedIdentityBackup,
  encryptedRecoveryBackup,
  recoveryPhrase,
  profile: { displayName: "Official Reels", badge: "Official", quickAddVisible: true, customStatus: "Fresh funny POVs" }
}));
const result = await onceMessage(ws, "account-response", requestId);
ws.close();
if (!result.ok) throw new Error(result.message || "Official Reels account creation failed.");
console.log(JSON.stringify({ ok: true, peerId, displayName: "Official Reels" }));

async function encryptBackup(value, secret) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 210000, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(value)));
  return { version: 1, kdf: "PBKDF2-SHA-256", salt: encode(salt), iv: encode(iv), data: encode(new Uint8Array(data)) };
}

function encode(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function onceOpen(ws) {
  return new Promise((resolve, reject) => {
    ws.once("open", resolve);
    ws.once("error", reject);
  });
}

function onceMessage(ws, type, requestId = "") {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${type}.`)), 20000);
    const onMessage = (raw) => {
      const message = JSON.parse(String(raw));
      if (message.type !== type || (requestId && message.requestId !== requestId)) return;
      clearTimeout(timer);
      ws.off("message", onMessage);
      resolve(message);
    };
    ws.on("message", onMessage);
  });
}
