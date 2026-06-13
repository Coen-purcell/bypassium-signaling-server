import http from "node:http";
import { randomUUID } from "node:crypto";
import Redis from "ioredis";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 10000);
const OFFLINE_MESSAGE_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_OFFLINE_MESSAGES_PER_USER = 100;
const REDIS_URL = process.env.REDIS_URL || process.env.RENDER_REDIS_URL || process.env.KEY_VALUE_URL || "";
const UPSTASH_REST_URL = process.env.UPSTASH_REDIS_REST_URL || "";
const UPSTASH_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const clients = new Map();
const memoryPublicKeys = new Map();
const memoryOfflineMessages = new Map();
const redis = createRedisClient();
const upstashRestEnabled = Boolean(!redis && UPSTASH_REST_URL && UPSTASH_REST_TOKEN);

const server = http.createServer(async (request, response) => {
  if (request.url === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      ok: true,
      storage: storageMode(),
      onlineClients: clients.size,
      knownPublicKeys: await countKnownPublicKeys(),
      queuedUsers: await countQueuedUsers()
    }));
    return;
  }

  response.writeHead(200, { "content-type": "text/plain" });
  response.end("Bypassium message server is running.");
});

const wss = new WebSocketServer({ server });

wss.on("connection", (socket) => {
  socket.bypassiumId = null;
  socket.publicKeyJwk = null;

  socket.on("message", async (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      send(socket, { type: "error", message: "Invalid message format." });
      return;
    }

    if (message.type === "register") await registerClient(socket, message);
    if (message.type === "watch-contacts") await sendContactStatuses(socket, message.contacts);
    if (message.type === "direct-message") await relayDirectMessage(socket, message);
    if (message.type === "ack-message") await acknowledgeMessage(socket, message);
  });

  socket.on("close", () => unregisterClient(socket));
});

function createRedisClient() {
  if (!REDIS_URL) return null;
  const client = new Redis(REDIS_URL, {
    lazyConnect: false,
    maxRetriesPerRequest: 2,
    enableReadyCheck: true
  });
  client.on("error", (error) => {
    console.error("Redis storage error:", error.message);
  });
  return client;
}

// Registers a permanent Bypassium ID and persists its public key for encrypted relay messages.
async function registerClient(socket, message) {
  const byPassiumId = String(message.peerId || "").trim();
  if (!/^\d{6}$/.test(byPassiumId) || !message.publicKeyJwk) {
    send(socket, { type: "error", message: "Registration requires a 6-digit ID and public key." });
    return;
  }

  unregisterClient(socket);
  socket.bypassiumId = byPassiumId;
  socket.publicKeyJwk = message.publicKeyJwk;
  await setPublicKey(byPassiumId, message.publicKeyJwk);
  if (!clients.has(byPassiumId)) clients.set(byPassiumId, new Set());
  clients.get(byPassiumId).add(socket);
  send(socket, {
    type: "registered",
    peerId: byPassiumId,
    features: {
      encryptedRelay: true,
      offlineInbox: true,
      ackedOfflineInbox: true,
      persistentOfflineInbox: storageMode() !== "memory",
      publicKeyDirectory: true
    }
  });
  await deliverOfflineMessages(socket);
}

// Removes a browser session from the online directory without deleting its persisted public key.
function unregisterClient(socket) {
  if (!socket.bypassiumId) return;
  const sockets = clients.get(socket.bypassiumId);
  if (sockets) {
    sockets.delete(socket);
    if (sockets.size === 0) clients.delete(socket.bypassiumId);
  }
  socket.bypassiumId = null;
}

// Reports which saved contacts are online and returns public keys known to the server.
async function sendContactStatuses(socket, contacts = []) {
  const statuses = {};
  const knownKeys = {};
  for (const rawContactId of contacts) {
    const contactId = String(rawContactId || "").trim();
    if (!/^\d{6}$/.test(contactId)) continue;
    statuses[contactId] = clients.has(contactId) ? "online" : "offline";
    const publicKeyJwk = await getPublicKey(contactId);
    if (publicKeyJwk) knownKeys[contactId] = publicKeyJwk;
  }
  send(socket, { type: "contact-statuses", statuses, publicKeys: knownKeys });
}

function getRegisteredSender(socket) {
  if (!socket.bypassiumId) {
    send(socket, { type: "error", message: "Register before sending direct messages." });
    return null;
  }
  return socket.bypassiumId;
}

// Relays encrypted message envelopes or queues them until the receiver reconnects.
async function relayDirectMessage(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;

  const targetId = String(message.to || "").trim();
  if (!/^\d{6}$/.test(targetId) || !message.encrypted) {
    send(socket, { type: "error", message: "Message target or encrypted payload is invalid." });
    return;
  }

  const envelope = {
    type: "direct-message",
    messageId: message.messageId || randomUUID(),
    from: senderId,
    publicKeyJwk: socket.publicKeyJwk,
    encrypted: message.encrypted,
    sentAt: message.sentAt || new Date().toISOString()
  };
  const targets = clients.get(targetId);
  await queueOfflineMessage(targetId, envelope);

  if (!targets?.size) {
    send(socket, { type: "message-queued", peerId: targetId, sentAt: envelope.sentAt, persistent: storageMode() !== "memory" });
    return;
  }

  for (const target of targets) {
    if (target !== socket && target.readyState === 1) send(target, envelope);
  }
  send(socket, { type: "message-relayed", peerId: targetId, sentAt: envelope.sentAt });
}

// Deletes a queued encrypted message only after the recipient extension saved it locally.
async function acknowledgeMessage(socket, message) {
  const targetId = getRegisteredSender(socket);
  if (!targetId) return;
  const messageId = String(message.messageId || "").trim();
  if (!messageId) {
    send(socket, { type: "error", message: "Acknowledgement requires a message ID." });
    return;
  }
  await removeOfflineMessage(targetId, messageId);
  send(socket, { type: "message-acknowledged", messageId });
}

// Stores encrypted messages only. Redis makes them survive Render service restarts.
async function queueOfflineMessage(targetId, envelope) {
  if (redis) {
    const key = inboxKey(targetId);
    await redis.rpush(key, JSON.stringify({ ...envelope, queuedAt: Date.now() }));
    await redis.ltrim(key, -MAX_OFFLINE_MESSAGES_PER_USER, -1);
    await redis.expire(key, OFFLINE_MESSAGE_TTL_SECONDS);
    return;
  }

  if (upstashRestEnabled) {
    const key = inboxKey(targetId);
    await upstashCommand(["RPUSH", key, JSON.stringify({ ...envelope, queuedAt: Date.now() })]);
    await upstashCommand(["LTRIM", key, -MAX_OFFLINE_MESSAGES_PER_USER, -1]);
    await upstashCommand(["EXPIRE", key, OFFLINE_MESSAGE_TTL_SECONDS]);
    return;
  }

  const queue = memoryOfflineMessages.get(targetId) || [];
  queue.push({ ...envelope, queuedAt: Date.now() });
  memoryOfflineMessages.set(targetId, queue.slice(-MAX_OFFLINE_MESSAGES_PER_USER));
}

// Delivers queued messages with their original sentAt time. Messages stay queued until acked.
async function deliverOfflineMessages(socket) {
  const queue = await getOfflineMessages(socket.bypassiumId);
  const fresh = queue.filter((message) => Date.now() - message.queuedAt <= OFFLINE_MESSAGE_TTL_SECONDS * 1000);
  for (const message of fresh) send(socket, message);
  if (fresh.length !== queue.length) await replaceOfflineMessages(socket.bypassiumId, fresh);
}

async function getOfflineMessages(targetId) {
  if (redis) {
    const stored = await redis.lrange(inboxKey(targetId), 0, -1);
    return stored.map((item) => JSON.parse(item));
  }
  if (upstashRestEnabled) {
    const stored = await upstashCommand(["LRANGE", inboxKey(targetId), 0, -1]);
    return stored.map((item) => JSON.parse(item));
  }
  return memoryOfflineMessages.get(targetId) || [];
}

async function removeOfflineMessage(targetId, messageId) {
  const queue = await getOfflineMessages(targetId);
  const remaining = queue.filter((message) => message.messageId !== messageId);
  if (remaining.length !== queue.length) await replaceOfflineMessages(targetId, remaining);
}

async function replaceOfflineMessages(targetId, messages) {
  if (redis) {
    const key = inboxKey(targetId);
    await redis.del(key);
    if (messages.length) {
      await redis.rpush(key, ...messages.map((message) => JSON.stringify(message)));
      await redis.expire(key, OFFLINE_MESSAGE_TTL_SECONDS);
    }
    return;
  }
  if (upstashRestEnabled) {
    const key = inboxKey(targetId);
    await upstashCommand(["DEL", key]);
    if (messages.length) {
      await upstashCommand(["RPUSH", key, ...messages.map((message) => JSON.stringify(message))]);
      await upstashCommand(["EXPIRE", key, OFFLINE_MESSAGE_TTL_SECONDS]);
    }
    return;
  }
  if (messages.length) memoryOfflineMessages.set(targetId, messages);
  else memoryOfflineMessages.delete(targetId);
}

async function setPublicKey(peerId, publicKeyJwk) {
  memoryPublicKeys.set(peerId, publicKeyJwk);
  if (redis) await redis.set(publicKeyKey(peerId), JSON.stringify(publicKeyJwk));
  if (upstashRestEnabled) await upstashCommand(["SET", publicKeyKey(peerId), JSON.stringify(publicKeyJwk)]);
}

async function getPublicKey(peerId) {
  if (memoryPublicKeys.has(peerId)) return memoryPublicKeys.get(peerId);
  let stored = null;
  if (redis) stored = await redis.get(publicKeyKey(peerId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", publicKeyKey(peerId)]);
  if (!stored) return null;
  const publicKeyJwk = JSON.parse(stored);
  memoryPublicKeys.set(peerId, publicKeyJwk);
  return publicKeyJwk;
}

async function countKnownPublicKeys() {
  if (!redis && !upstashRestEnabled) return memoryPublicKeys.size;
  return countKeys("bypassium:public-key:*");
}

async function countQueuedUsers() {
  if (!redis && !upstashRestEnabled) return memoryOfflineMessages.size;
  return countKeys("bypassium:inbox:*");
}

async function countKeys(pattern) {
  if (upstashRestEnabled) return countUpstashKeys(pattern);

  let cursor = "0";
  let count = 0;
  do {
    const [nextCursor, keys] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 100);
    cursor = nextCursor;
    count += keys.length;
  } while (cursor !== "0");
  return count;
}

async function countUpstashKeys(pattern) {
  let cursor = "0";
  let count = 0;
  do {
    const [nextCursor, keys] = await upstashCommand(["SCAN", cursor, "MATCH", pattern, "COUNT", 100]);
    cursor = String(nextCursor);
    count += keys.length;
  } while (cursor !== "0");
  return count;
}

async function upstashCommand(command) {
  const response = await fetch(UPSTASH_REST_URL, {
    method: "POST",
    headers: {
      authorization: `Bearer ${UPSTASH_REST_TOKEN}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(command)
  });
  const payload = await response.json();
  if (!response.ok || payload.error) {
    throw new Error(payload.error || `Upstash command failed with ${response.status}`);
  }
  return payload.result;
}

function storageMode() {
  if (redis) return "redis";
  if (upstashRestEnabled) return "upstash-rest";
  return "memory";
}

function publicKeyKey(peerId) {
  return `bypassium:public-key:${peerId}`;
}

function inboxKey(peerId) {
  return `bypassium:inbox:${peerId}`;
}

function send(socket, message) {
  if (socket.readyState === 1) socket.send(JSON.stringify(message));
}

server.listen(PORT, () => {
  console.log(`Bypassium message server listening on ${PORT}`);
});
