import http from "node:http";
import { randomUUID } from "node:crypto";
import Redis from "ioredis";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 10000);
const OFFLINE_MESSAGE_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_OFFLINE_MESSAGES_PER_USER = 50;
const MAX_PROFILE_PICTURE_CHARS = 18000;
const REDIS_URL = process.env.REDIS_URL || process.env.RENDER_REDIS_URL || process.env.KEY_VALUE_URL || "";
const UPSTASH_REST_URL = process.env.UPSTASH_REDIS_REST_URL || "";
const UPSTASH_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const clients = new Map();
const memoryPublicKeys = new Map();
const memoryProfiles = new Map();
const memoryGroups = new Map();
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
      groups: await countGroups(),
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
    if (message.type === "publish-profile") await publishProfile(socket, message.profile);
    if (message.type === "create-group") await createGroup(socket, message);
    if (message.type === "rename-group") await renameGroup(socket, message);
    if (message.type === "add-group-members") await addGroupMembers(socket, message);
    if (message.type === "leave-group") await leaveGroup(socket, message);
    if (message.type === "direct-message") await relayDirectMessage(socket, message);
    if (message.type === "group-message") await relayGroupMessage(socket, message);
    if (message.type === "ack-message") await acknowledgeMessage(socket, message);
    if (message.type === "typing") await relayTyping(socket, message);
    if (message.type === "read-receipt") await relayReadReceipt(socket, message);
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
    groups: await getGroupsForMember(byPassiumId),
    features: {
      encryptedRelay: true,
      offlineInbox: true,
      ackedOfflineInbox: true,
      persistentOfflineInbox: storageMode() !== "memory",
      publicKeyDirectory: true,
      profiles: true,
      groups: true
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
  const profiles = {};
  socket.watchedContacts = new Set();
  for (const rawContactId of contacts) {
    const contactId = String(rawContactId || "").trim();
    if (!/^\d{6}$/.test(contactId)) continue;
    socket.watchedContacts.add(contactId);
    statuses[contactId] = clients.has(contactId) ? "online" : "offline";
    const publicKeyJwk = await getPublicKey(contactId);
    if (publicKeyJwk) knownKeys[contactId] = publicKeyJwk;
    const profile = await getProfile(contactId);
    if (profile) profiles[contactId] = profile;
  }
  send(socket, { type: "contact-statuses", statuses, publicKeys: knownKeys, profiles });
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
    profile: sanitizeProfile(await getProfile(senderId)),
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

// Relays one encrypted group message copy per recipient and queues each copy until acked.
async function relayGroupMessage(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(senderId)) {
    send(socket, { type: "error", message: "You are not a member of this group." });
    return;
  }
  const recipients = Array.isArray(message.recipients) ? message.recipients : [];
  const sentAt = message.sentAt || new Date().toISOString();
  const messageId = message.messageId || randomUUID();
  for (const recipient of recipients) {
    const targetId = String(recipient.to || "").trim();
    if (targetId === senderId || !group.members.includes(targetId) || !recipient.encrypted) continue;
    const envelope = {
      type: "group-message",
      messageId,
      groupId: group.id,
      groupName: group.name,
      members: group.members,
      from: senderId,
      profile: sanitizeProfile(await getProfile(senderId)),
      publicKeyJwk: socket.publicKeyJwk,
      encrypted: recipient.encrypted,
      sentAt
    };
    await queueOfflineMessage(targetId, envelope);
    const targets = clients.get(targetId);
    if (targets?.size) {
      for (const target of targets) {
        if (target !== socket && target.readyState === 1) send(target, envelope);
      }
    }
  }
  send(socket, { type: "message-relayed", peerId: group.id, sentAt });
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

async function relayTyping(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  const groupId = String(message.groupId || "").trim();
  if (groupId) {
    const group = await getGroup(groupId);
    if (!group || !group.members.includes(senderId)) return;
    for (const memberId of group.members) {
      if (memberId === senderId) continue;
      sendToClient(memberId, {
        type: "typing",
        from: senderId,
        groupId,
        isTyping: Boolean(message.isTyping)
      }, socket);
    }
    return;
  }

  const targetId = String(message.to || "").trim();
  if (!/^\d{6}$/.test(targetId)) return;
  sendToClient(targetId, {
    type: "typing",
    from: senderId,
    isTyping: Boolean(message.isTyping)
  }, socket);
}

async function relayReadReceipt(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  const targetId = String(message.to || "").trim();
  const messageId = String(message.messageId || "").trim();
  if (!/^\d{6}$/.test(targetId) || !messageId) return;
  sendToClient(targetId, {
    type: "read-receipt",
    from: senderId,
    messageId,
    readAt: message.readAt || new Date().toISOString()
  }, socket);
}

// Stores a user's public profile so contacts can display their current picture.
async function publishProfile(socket, profile = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const cleanProfile = sanitizeProfile(profile, true);
  await setProfile(peerId, cleanProfile);
  broadcastProfileUpdate(peerId, cleanProfile);
}

async function createGroup(socket, message) {
  const creatorId = getRegisteredSender(socket);
  if (!creatorId) return;
  const members = normalizeMembers([creatorId, ...(message.members || [])]);
  const group = {
    id: randomUUID(),
    name: String(message.name || "New group").slice(0, 80),
    members,
    createdBy: creatorId,
    updatedAt: new Date().toISOString()
  };
  await setGroup(group);
  broadcastGroupUpdate(group);
}

async function renameGroup(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(peerId)) return;
  group.name = String(message.name || group.name).slice(0, 80);
  group.updatedAt = new Date().toISOString();
  await setGroup(group);
  broadcastGroupUpdate(group);
}

async function addGroupMembers(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(peerId)) return;
  group.members = normalizeMembers([...group.members, ...(message.members || [])]);
  group.updatedAt = new Date().toISOString();
  await setGroup(group);
  broadcastGroupUpdate(group);
}

async function leaveGroup(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(peerId)) return;
  group.members = group.members.filter((member) => member !== peerId);
  group.updatedAt = new Date().toISOString();
  if (group.members.length) {
    await setGroup(group);
    broadcastGroupUpdate(group, [peerId]);
  } else {
    await deleteGroup(group.id);
  }
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

async function setProfile(peerId, profile) {
  memoryProfiles.set(peerId, profile);
  if (redis) await redis.set(profileKey(peerId), JSON.stringify(profile));
  if (upstashRestEnabled) await upstashCommand(["SET", profileKey(peerId), JSON.stringify(profile)]);
}

async function getProfile(peerId) {
  if (memoryProfiles.has(peerId)) return memoryProfiles.get(peerId);
  let stored = null;
  if (redis) stored = await redis.get(profileKey(peerId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", profileKey(peerId)]);
  if (!stored) return null;
  const profile = JSON.parse(stored);
  memoryProfiles.set(peerId, profile);
  return profile;
}

async function setGroup(group) {
  memoryGroups.set(group.id, group);
  if (redis) await redis.set(groupKey(group.id), JSON.stringify(group));
  if (upstashRestEnabled) await upstashCommand(["SET", groupKey(group.id), JSON.stringify(group)]);
}

async function getGroup(groupId) {
  const cleanGroupId = String(groupId || "").trim();
  if (!cleanGroupId) return null;
  if (memoryGroups.has(cleanGroupId)) return memoryGroups.get(cleanGroupId);
  let stored = null;
  if (redis) stored = await redis.get(groupKey(cleanGroupId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", groupKey(cleanGroupId)]);
  if (!stored) return null;
  const group = JSON.parse(stored);
  memoryGroups.set(group.id, group);
  return group;
}

async function deleteGroup(groupId) {
  memoryGroups.delete(groupId);
  if (redis) await redis.del(groupKey(groupId));
  if (upstashRestEnabled) await upstashCommand(["DEL", groupKey(groupId)]);
}

async function getGroupsForMember(peerId) {
  const groups = await getAllGroups();
  return groups.filter((group) => group.members.includes(peerId));
}

async function getAllGroups() {
  if (!redis && !upstashRestEnabled) return [...memoryGroups.values()];
  const keys = await listKeys("bypassium:group:*");
  const groups = [];
  for (const key of keys) {
    let stored = null;
    if (redis) stored = await redis.get(key);
    if (upstashRestEnabled) stored = await upstashCommand(["GET", key]);
    if (stored) groups.push(JSON.parse(stored));
  }
  return groups;
}

function broadcastGroupUpdate(group, extraMemberIds = []) {
  for (const memberId of normalizeMembers([...group.members, ...extraMemberIds])) {
    const sockets = clients.get(memberId);
    if (!sockets) continue;
    for (const socket of sockets) send(socket, { type: "group-updated", group });
  }
}

function broadcastProfileUpdate(peerId, profile) {
  for (const sockets of clients.values()) {
    for (const socket of sockets) {
      if (socket.watchedContacts?.has(peerId)) send(socket, { type: "profile-updated", peerId, profile });
    }
  }
}

function normalizeMembers(members) {
  return [...new Set(members.map((member) => String(member || "").trim()).filter((member) => /^\d{6}$/.test(member)))];
}

async function countKnownPublicKeys() {
  if (!redis && !upstashRestEnabled) return memoryPublicKeys.size;
  return countKeys("bypassium:public-key:*");
}

async function countGroups() {
  if (!redis && !upstashRestEnabled) return memoryGroups.size;
  return countKeys("bypassium:group:*");
}

async function countQueuedUsers() {
  if (!redis && !upstashRestEnabled) return memoryOfflineMessages.size;
  return countKeys("bypassium:inbox:*");
}

async function countKeys(pattern) {
  const keys = await listKeys(pattern);
  return keys.length;
}

async function listKeys(pattern) {
  if (upstashRestEnabled) return countUpstashKeys(pattern);

  let cursor = "0";
  let found = [];
  do {
    const [nextCursor, keys] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 100);
    cursor = nextCursor;
    found = found.concat(keys);
  } while (cursor !== "0");
  return found;
}

async function countUpstashKeys(pattern) {
  let cursor = "0";
  let found = [];
  do {
    const [nextCursor, keys] = await upstashCommand(["SCAN", cursor, "MATCH", pattern, "COUNT", 100]);
    cursor = String(nextCursor);
    found = found.concat(keys);
  } while (cursor !== "0");
  return found;
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

function sanitizeProfile(profile = {}, stampUpdate = false) {
  const cleanProfile = {
    displayName: String(profile?.displayName || "").slice(0, 80),
    profilePicture: sanitizeProfilePicture(profile?.profilePicture)
  };
  if (stampUpdate) cleanProfile.updatedAt = new Date().toISOString();
  else if (profile?.updatedAt) cleanProfile.updatedAt = String(profile.updatedAt).slice(0, 40);
  return cleanProfile;
}

function sanitizeProfilePicture(value = "") {
  const picture = String(value || "");
  if (!picture) return "";
  if (!picture.startsWith("data:image/")) return "";
  return picture.slice(0, MAX_PROFILE_PICTURE_CHARS);
}

function publicKeyKey(peerId) {
  return `bypassium:public-key:${peerId}`;
}

function profileKey(peerId) {
  return `bypassium:profile:${peerId}`;
}

function groupKey(groupId) {
  return `bypassium:group:${groupId}`;
}

function inboxKey(peerId) {
  return `bypassium:inbox:${peerId}`;
}

function sendToClient(peerId, message, exceptSocket = null) {
  const sockets = clients.get(peerId);
  if (!sockets) return;
  for (const socket of sockets) {
    if (socket !== exceptSocket && socket.readyState === 1) send(socket, message);
  }
}

function send(socket, message) {
  if (socket.readyState === 1) socket.send(JSON.stringify(message));
}

server.listen(PORT, () => {
  console.log(`Bypassium message server listening on ${PORT}`);
});
