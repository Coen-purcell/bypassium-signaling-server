import http from "node:http";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 10000);
const OFFLINE_MESSAGE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_OFFLINE_MESSAGES_PER_USER = 100;
const clients = new Map();
const publicKeys = new Map();
const offlineMessages = new Map();

const server = http.createServer((request, response) => {
  if (request.url === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({
      ok: true,
      onlineClients: clients.size,
      knownPublicKeys: publicKeys.size,
      queuedUsers: offlineMessages.size
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

  socket.on("message", (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      send(socket, { type: "error", message: "Invalid message format." });
      return;
    }

    if (message.type === "register") registerClient(socket, message);
    if (message.type === "watch-contacts") sendContactStatuses(socket, message.contacts);
    if (message.type === "direct-message") relayDirectMessage(socket, message);
  });

  socket.on("close", () => unregisterClient(socket));
});

// Registers a permanent Bypassium ID and keeps its public key available for encrypted relay messages.
function registerClient(socket, message) {
  const byPassiumId = String(message.peerId || "").trim();
  if (!/^\d{6}$/.test(byPassiumId) || !message.publicKeyJwk) {
    send(socket, { type: "error", message: "Registration requires a 6-digit ID and public key." });
    return;
  }

  unregisterClient(socket);
  socket.bypassiumId = byPassiumId;
  socket.publicKeyJwk = message.publicKeyJwk;
  publicKeys.set(byPassiumId, message.publicKeyJwk);
  if (!clients.has(byPassiumId)) clients.set(byPassiumId, new Set());
  clients.get(byPassiumId).add(socket);
  send(socket, {
    type: "registered",
    peerId: byPassiumId,
    features: {
      encryptedRelay: true,
      offlineInbox: true,
      publicKeyDirectory: true
    }
  });
  deliverOfflineMessages(socket);
}

// Removes a browser session from the online directory without deleting its known public key.
function unregisterClient(socket) {
  if (!socket.bypassiumId) return;
  const sockets = clients.get(socket.bypassiumId);
  if (sockets) {
    sockets.delete(socket);
    if (sockets.size === 0) clients.delete(socket.bypassiumId);
  }
  socket.bypassiumId = null;
}

// Reports which saved contacts are online and returns public keys that are known to the server.
function sendContactStatuses(socket, contacts = []) {
  const statuses = {};
  const knownKeys = {};
  for (const rawContactId of contacts) {
    const contactId = String(rawContactId || "").trim();
    if (!/^\d{6}$/.test(contactId)) continue;
    statuses[contactId] = clients.has(contactId) ? "online" : "offline";
    if (publicKeys.has(contactId)) knownKeys[contactId] = publicKeys.get(contactId);
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
function relayDirectMessage(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;

  const targetId = String(message.to || "").trim();
  if (!/^\d{6}$/.test(targetId) || !message.encrypted) {
    send(socket, { type: "error", message: "Message target or encrypted payload is invalid." });
    return;
  }

  const envelope = {
    type: "direct-message",
    from: senderId,
    publicKeyJwk: socket.publicKeyJwk,
    encrypted: message.encrypted,
    sentAt: message.sentAt || new Date().toISOString()
  };
  const targets = clients.get(targetId);

  if (!targets?.size) {
    queueOfflineMessage(targetId, envelope);
    send(socket, { type: "message-queued", peerId: targetId, sentAt: envelope.sentAt });
    return;
  }

  for (const target of targets) {
    if (target !== socket && target.readyState === 1) send(target, envelope);
  }
  send(socket, { type: "message-relayed", peerId: targetId, sentAt: envelope.sentAt });
}

// Stores encrypted messages only. The server cannot decrypt message text.
function queueOfflineMessage(targetId, envelope) {
  const queue = offlineMessages.get(targetId) || [];
  queue.push({ ...envelope, queuedAt: Date.now() });
  offlineMessages.set(targetId, queue.slice(-MAX_OFFLINE_MESSAGES_PER_USER));
}

// Delivers queued messages with their original sentAt time, then deletes them from memory.
function deliverOfflineMessages(socket) {
  const queue = offlineMessages.get(socket.bypassiumId) || [];
  const fresh = queue.filter((message) => Date.now() - message.queuedAt <= OFFLINE_MESSAGE_TTL_MS);
  for (const message of fresh) send(socket, message);
  offlineMessages.delete(socket.bypassiumId);
}

function send(socket, message) {
  if (socket.readyState === 1) socket.send(JSON.stringify(message));
}

server.listen(PORT, () => {
  console.log(`Bypassium message server listening on ${PORT}`);
});
