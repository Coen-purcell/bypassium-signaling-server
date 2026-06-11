import http from "node:http";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 10000);
const ROOM_TTL_MS = 10 * 60 * 1000;
const rooms = new Map();
const clients = new Map();

const server = http.createServer((request, response) => {
  if (request.url === "/health") {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true, rooms: rooms.size, onlineClients: clients.size }));
    return;
  }

  response.writeHead(200, { "content-type": "text/plain" });
  response.end("Bypassium signaling server is running.");
});

const wss = new WebSocketServer({ server });

wss.on("connection", (socket) => {
  socket.peerId = crypto.randomUUID();
  socket.bypassiumId = null;
  socket.publicKeyJwk = null;
  socket.roomCode = null;

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
    if (message.type === "direct-signal") relayDirectSignal(socket, message);
    if (message.type === "create-room") createRoom(socket);
    if (message.type === "join-room") joinRoom(socket, message.code);
    if (message.type === "signal") relayRoomSignal(socket, message);
    if (message.type === "leave-room") leaveRoom(socket);
  });

  socket.on("close", () => {
    leaveRoom(socket);
    unregisterClient(socket);
  });
});

// Registers a permanent Bypassium ID while this browser session is online.
function registerClient(socket, message) {
  const byPassiumId = String(message.peerId || "").trim();
  if (!/^\d{6}$/.test(byPassiumId) || !message.publicKeyJwk) {
    send(socket, { type: "error", message: "Registration requires a 6-digit ID and public key." });
    return;
  }

  unregisterClient(socket);
  socket.bypassiumId = byPassiumId;
  socket.publicKeyJwk = message.publicKeyJwk;
  if (!clients.has(byPassiumId)) clients.set(byPassiumId, new Set());
  clients.get(byPassiumId).add(socket);
  send(socket, { type: "registered", peerId: byPassiumId });
}

// Removes a browser session from the online directory.
function unregisterClient(socket) {
  if (!socket.bypassiumId) return;
  const sockets = clients.get(socket.bypassiumId);
  if (sockets) {
    sockets.delete(socket);
    if (sockets.size === 0) clients.delete(socket.bypassiumId);
  }
  socket.bypassiumId = null;
}

// Reports which saved contacts are currently reachable through the signaling server.
function sendContactStatuses(socket, contacts = []) {
  const statuses = {};
  for (const contactId of contacts) statuses[contactId] = clients.has(String(contactId)) ? "online" : "offline";
  send(socket, { type: "contact-statuses", statuses });
}

// Relays WebRTC setup messages between permanent IDs without storing chat data.
function relayDirectSignal(socket, message) {
  if (!socket.bypassiumId) {
    send(socket, { type: "error", message: "Register before sending direct signals." });
    return;
  }

  const targetId = String(message.to || "").trim();
  const targets = clients.get(targetId);
  if (!targets?.size) {
    send(socket, { type: "peer-offline", peerId: targetId });
    return;
  }

  for (const target of targets) {
    if (target !== socket && target.readyState === 1) {
      send(target, {
        type: "direct-signal",
        from: socket.bypassiumId,
        publicKeyJwk: socket.publicKeyJwk,
        signalType: message.signalType,
        payload: message.payload
      });
    }
  }
}

// Creates a temporary six-digit room for two peers to exchange WebRTC setup data.
function createRoom(socket) {
  leaveRoom(socket);
  const code = createUniqueCode();
  rooms.set(code, {
    createdAt: Date.now(),
    peers: new Set([socket])
  });
  socket.roomCode = code;
  send(socket, { type: "room-created", code });
}

// Joins an existing room and notifies both peers that signaling can begin.
function joinRoom(socket, code) {
  const room = rooms.get(String(code || "").trim());
  if (!room) {
    send(socket, { type: "error", message: "That connection code was not found." });
    return;
  }
  if (room.peers.size >= 2) {
    send(socket, { type: "error", message: "That connection code is already in use." });
    return;
  }

  leaveRoom(socket);
  room.peers.add(socket);
  socket.roomCode = code;
  broadcast(room, { type: "peer-ready" });
}

// Relays WebRTC setup messages to the other peer in the same temporary code room.
function relayRoomSignal(socket, message) {
  const room = rooms.get(socket.roomCode);
  if (!room) {
    send(socket, { type: "error", message: "You are not in a connection room." });
    return;
  }

  for (const peer of room.peers) {
    if (peer !== socket && peer.readyState === peer.OPEN) {
      send(peer, {
        type: "signal",
        signalType: message.signalType,
        payload: message.payload
      });
    }
  }
}

// Removes a socket from its current room and deletes empty rooms.
function leaveRoom(socket) {
  if (!socket.roomCode) return;
  const room = rooms.get(socket.roomCode);
  if (room) {
    room.peers.delete(socket);
    broadcast(room, { type: "peer-left" });
    if (room.peers.size === 0) rooms.delete(socket.roomCode);
  }
  socket.roomCode = null;
}

function send(socket, message) {
  if (socket.readyState === 1) socket.send(JSON.stringify(message));
}

function broadcast(room, message) {
  for (const peer of room.peers) send(peer, message);
}

function createUniqueCode() {
  for (let attempts = 0; attempts < 25; attempts += 1) {
    const code = String(Math.floor(Math.random() * 1000000)).padStart(6, "0");
    if (!rooms.has(code)) return code;
  }
  throw new Error("Could not allocate a room code.");
}

setInterval(() => {
  const now = Date.now();
  for (const [code, room] of rooms) {
    if (now - room.createdAt > ROOM_TTL_MS) {
      broadcast(room, { type: "room-expired" });
      for (const peer of room.peers) peer.close();
      rooms.delete(code);
    }
  }
}, 30 * 1000).unref();

server.listen(PORT, () => {
  console.log(`Bypassium signaling server listening on ${PORT}`);
});
