import http from "node:http";
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import Redis from "ioredis";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 10000);
const OFFLINE_MESSAGE_TTL_SECONDS = 7 * 24 * 60 * 60;
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const MAX_OFFLINE_MESSAGES_PER_USER = 30;
const MAX_PROFILE_PICTURE_CHARS = 18000;
const MAX_UPSTASH_RPUSH_ITEMS = 4;
const MAX_UPSTASH_RPUSH_CHARS = 6_000_000;
const MAX_UPSTASH_COMMAND_CHARS = 8_500_000;
const MAX_QUEUED_ENVELOPE_CHARS = 4_500_000;
const MAX_WEBSOCKET_PAYLOAD_CHARS = 6_000_000;
const REDIS_URL = process.env.REDIS_URL || process.env.RENDER_REDIS_URL || process.env.KEY_VALUE_URL || "";
const UPSTASH_REST_URL = process.env.UPSTASH_REDIS_REST_URL || "";
const UPSTASH_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const clients = new Map();
const sessions = new Map();
const memoryPublicKeys = new Map();
const memoryProfiles = new Map();
const memoryAccounts = new Map();
const memoryDirectory = new Map();
const memoryGroups = new Map();
const memoryOfflineMessages = new Map();
const pendingQueuedEnvelopes = new Map();
const cancelledQueuedEnvelopes = new Set();
const redis = createRedisClient();
const upstashRestEnabled = Boolean(!redis && UPSTASH_REST_URL && UPSTASH_REST_TOKEN);

const server = http.createServer(async (request, response) => {
  const corsHeaders = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, OPTIONS",
    "access-control-allow-headers": "content-type"
  };
  if (request.method === "OPTIONS") {
    response.writeHead(204, corsHeaders);
    response.end();
    return;
  }

  if (request.url === "/health") {
    response.writeHead(200, { ...corsHeaders, "content-type": "application/json" });
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

  response.writeHead(200, { ...corsHeaders, "content-type": "text/plain" });
  response.end("Bypassium message server is running.");
});

const wss = new WebSocketServer({ server, maxPayload: MAX_WEBSOCKET_PAYLOAD_CHARS });

wss.on("connection", (socket, request) => {
  socket.bypassiumId = null;
  socket.publicKeyJwk = null;
  socket.remoteAddress = String(request?.socket?.remoteAddress || "");

  socket.on("message", async (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      send(socket, { type: "error", message: "Invalid message format." });
      return;
    }

    try {
      if (message.type === "register") await registerClient(socket, message);
      if (message.type === "account-status") await sendAccountStatus(socket, message);
      if (message.type === "create-account") await createAccount(socket, message);
      if (message.type === "claim-legacy-account") await claimLegacyAccount(socket, message);
      if (message.type === "sign-in") await signInAccount(socket, message);
      if (message.type === "session-sign-in") await signInWithSession(socket, message);
      if (message.type === "change-password") await changePassword(socket, message);
      if (message.type === "account-search") await searchAccounts(socket, message);
      if (message.type === "recover-account") await recoverAccount(socket, message);
      if (message.type === "reset-password-with-recovery") await resetPasswordWithRecovery(socket, message);
      if (message.type === "sign-out") await signOutAccount(socket, message);
      if (message.type === "delete-account") await deleteAccount(socket, message);
      if (message.type === "watch-contacts") await sendContactStatuses(socket, message.contacts);
      if (message.type === "publish-profile") await publishProfile(socket, message.profile);
      if (message.type === "quick-add-request") await sendQuickAddResults(socket, message);
      if (message.type === "create-group") await createGroup(socket, message);
      if (message.type === "rename-group") await renameGroup(socket, message);
      if (message.type === "update-group") await updateGroupDetails(socket, message);
      if (message.type === "add-group-members") await addGroupMembers(socket, message);
      if (message.type === "set-group-admin") await setGroupAdmin(socket, message);
      if (message.type === "transfer-group-ownership") await transferGroupOwnership(socket, message);
      if (message.type === "remove-group-member") await removeGroupMember(socket, message);
      if (message.type === "leave-group") await leaveGroup(socket, message);
      if (message.type === "direct-message") await relayDirectMessage(socket, message);
      if (message.type === "direct-setting") await relayDirectSetting(socket, message);
      if (message.type === "group-message") await relayGroupMessage(socket, message);
      if (message.type === "ack-message") await acknowledgeMessage(socket, message);
      if (message.type === "typing") await relayTyping(socket, message);
      if (message.type === "read-receipt") await relayReadReceipt(socket, message);
      if (message.type === "reaction") await relayReaction(socket, message);
      if (message.type === "sync") await syncClient(socket);
    } catch (error) {
      console.error("Message handler failed:", error.message);
      send(socket, { type: "error", message: "The message server could not process that request. Try again in a moment." });
    }
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
  const account = await getAccount(byPassiumId);
  const storedPublicKey = await getPublicKey(byPassiumId);
  const storedKeyMatches = !storedPublicKey || samePublicKey(storedPublicKey, message.publicKeyJwk);
  if (account?.passwordHash && !storedKeyMatches && !(await validSession(byPassiumId, message.sessionToken))) {
    send(socket, { type: "account-auth-required", peerId: byPassiumId, message: "Sign in before using this Bypassium code on this device." });
    return;
  }
  if (!account?.passwordHash && !storedKeyMatches) {
    send(socket, { type: "legacy-claim-required", peerId: byPassiumId, message: "This code already belongs to another local identity. Sign in or use the original device." });
    return;
  }

  unregisterClient(socket);
  socket.bypassiumId = byPassiumId;
  socket.publicKeyJwk = message.publicKeyJwk;
  if (!storedPublicKey || !samePublicKey(storedPublicKey, message.publicKeyJwk)) {
    await setPublicKey(byPassiumId, message.publicKeyJwk);
  }
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
      groups: true,
      deliveryStatus: true,
      groupRoles: true,
      encryptedChatSettings: true,
      quickAddDirectory: true,
      accounts: true
    },
    account: publicAccountStatus(account, Boolean(account?.passwordHash))
  });
  await deliverOfflineMessages(socket);
}

async function syncClient(socket) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  send(socket, {
    type: "sync-complete",
    groups: await getGroupsForMember(peerId),
    syncedAt: new Date().toISOString()
  });
  await sendContactStatuses(socket, [...(socket.watchedContacts || [])]);
  await deliverOfflineMessages(socket);
}

// Removes a browser session from the online directory without deleting its persisted public key.
function unregisterClient(socket) {
  if (!socket.bypassiumId) return;
  const disconnectedId = socket.bypassiumId;
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

async function sendAccountStatus(socket, message = {}) {
  const peerId = String(message.peerId || socket.bypassiumId || "").trim();
  if (!/^\d{6}$/.test(peerId)) {
    send(socket, { type: "account-status-result", requestId: String(message.requestId || ""), ok: false, message: "Enter a valid 6-digit Bypassium code." });
    return;
  }
  const account = await getAccount(peerId);
  const publicKeyJwk = await getPublicKey(peerId);
  send(socket, {
    type: "account-status-result",
    requestId: String(message.requestId || ""),
    ok: true,
    peerId,
    exists: Boolean(account || publicKeyJwk),
    hasPassword: Boolean(account?.passwordHash),
    canClaimFromThisDevice: Boolean(socket.bypassiumId === peerId && socket.publicKeyJwk && publicKeyJwk && samePublicKey(socket.publicKeyJwk, publicKeyJwk)),
    profile: sanitizeProfile(account?.profile || await getProfile(peerId) || {})
  });
}

async function createAccount(socket, message = {}) {
  const peerId = String(message.peerId || socket.bypassiumId || "").trim();
  const password = String(message.password || "");
  const publicKeyJwk = message.publicKeyJwk || socket.publicKeyJwk;
  if (!/^\d{6}$/.test(peerId) || !publicKeyJwk) {
    sendAccountResponse(socket, message, false, "Account creation requires a 6-digit code and local identity.");
    return;
  }
  if (!validPassword(password)) {
    sendAccountResponse(socket, message, false, "Use at least 8 characters for your password.");
    return;
  }
  const encryptedIdentityBackup = sanitizeEncryptedBackup(message.encryptedIdentityBackup);
  const encryptedRecoveryBackup = sanitizeEncryptedBackup(message.encryptedRecoveryBackup);
  const recoveryPhrase = normalizeRecoveryPhrase(message.recoveryPhrase);
  if (!encryptedIdentityBackup?.data) {
    sendAccountResponse(socket, message, false, "Account creation needs an encrypted identity backup.");
    return;
  }
  if (!encryptedRecoveryBackup?.data || !validRecoveryPhrase(recoveryPhrase)) {
    sendAccountResponse(socket, message, false, "Account creation needs a recovery phrase backup.");
    return;
  }
  const existing = await getAccount(peerId);
  if (existing?.passwordHash) {
    sendAccountResponse(socket, message, false, "That Bypassium code already has a password. Sign in instead.");
    return;
  }
  const storedPublicKey = await getPublicKey(peerId);
  if (storedPublicKey && !samePublicKey(storedPublicKey, publicKeyJwk)) {
    sendAccountResponse(socket, message, false, "That code already belongs to another local identity.");
    return;
  }
  const now = new Date().toISOString();
  const account = {
    peerId,
    ...hashPassword(password),
    publicKeyJwk,
    encryptedIdentityBackup,
    encryptedRecoveryBackup,
    ...hashRecoveryPhrase(recoveryPhrase),
    profile: sanitizeProfile(message.profile || await getProfile(peerId) || {}),
    createdAt: existing?.createdAt || now,
    updatedAt: now
  };
  await setAccount(peerId, account);
  await setPublicKey(peerId, publicKeyJwk);
  if (account.profile) {
    await setProfile(peerId, account.profile);
    await updateQuickAddDirectory(peerId, account.profile);
  }
  const sessionToken = issueSession(peerId);
  sendAccountResponse(socket, message, true, "Account created.", { sessionToken, account: publicAccountStatus(account, true) });
}

async function claimLegacyAccount(socket, message = {}) {
  const peerId = socket.bypassiumId;
  if (!peerId || !socket.publicKeyJwk) {
    sendAccountResponse(socket, message, false, "Open this on the original signed-in Bypassium device.");
    return;
  }
  const storedPublicKey = await getPublicKey(peerId);
  if (!storedPublicKey || !samePublicKey(storedPublicKey, socket.publicKeyJwk)) {
    sendAccountResponse(socket, message, false, "This device does not match the saved identity for that code.");
    return;
  }
  await createAccount(socket, { ...message, peerId, publicKeyJwk: socket.publicKeyJwk });
}

async function signInAccount(socket, message = {}) {
  const peerId = String(message.peerId || "").trim();
  const password = String(message.password || "");
  const account = /^\d{6}$/.test(peerId) ? await getAccount(peerId) : null;
  if (!account?.passwordHash || !verifyPassword(password, account)) {
    sendAccountResponse(socket, message, false, "Code or password is incorrect.");
    return;
  }
  const sessionToken = issueSession(peerId);
  sendAccountResponse(socket, message, true, "Signed in.", {
    sessionToken,
    account: publicAccountStatus(account, true),
    encryptedIdentityBackup: account.encryptedIdentityBackup || null
  });
}

async function signInWithSession(socket, message = {}) {
  const peerId = String(message.peerId || "").trim();
  const sessionToken = String(message.sessionToken || "");
  const account = /^\d{6}$/.test(peerId) ? await getAccount(peerId) : null;
  if (!account?.passwordHash || !(await validSession(peerId, sessionToken))) {
    sendAccountResponse(socket, message, false, "Saved sign-in expired. Enter your password once to trust this device again.");
    return;
  }
  sendAccountResponse(socket, message, true, "Trusted device signed in.", {
    sessionToken,
    account: publicAccountStatus(account, true)
  });
}

async function changePassword(socket, message = {}) {
  const peerId = String(message.peerId || socket.bypassiumId || "").trim();
  const oldPassword = String(message.oldPassword || "");
  const newPassword = String(message.newPassword || "");
  const encryptedIdentityBackup = sanitizeEncryptedBackup(message.encryptedIdentityBackup);
  const publicKeyJwk = message.publicKeyJwk || socket.publicKeyJwk || null;
  const account = /^\d{6}$/.test(peerId) ? await getAccount(peerId) : null;
  if (!account?.passwordHash || !verifyPassword(oldPassword, account)) {
    sendAccountResponse(socket, message, false, "Old password is incorrect.");
    return;
  }
  if (!validPassword(newPassword) || !encryptedIdentityBackup?.data || !publicKeyJwk) {
    sendAccountResponse(socket, message, false, "Choose a valid new password and identity backup.");
    return;
  }

  await revokePeerSessions(peerId);
  const now = new Date().toISOString();
  const updated = sanitizeAccount({
    ...account,
    ...hashPassword(newPassword),
    publicKeyJwk,
    encryptedIdentityBackup,
    updatedAt: now
  });
  await setAccount(peerId, updated);
  await setPublicKey(peerId, publicKeyJwk);
  const sessionToken = issueSession(peerId);
  sendAccountResponse(socket, message, true, "Password changed.", {
    sessionToken,
    account: publicAccountStatus(updated, true),
    encryptedIdentityBackup: updated.encryptedIdentityBackup || null
  });
}

async function recoverAccount(socket, message = {}) {
  const peerId = String(message.peerId || "").trim();
  const recoveryPhrase = normalizeRecoveryPhrase(message.recoveryPhrase);
  const account = /^\d{6}$/.test(peerId) ? await getAccount(peerId) : null;
  if (!account?.recoveryHash || !verifyRecoveryPhrase(recoveryPhrase, account)) {
    sendAccountResponse(socket, message, false, "Code or recovery phrase is incorrect.");
    return;
  }
  sendAccountResponse(socket, message, true, "Recovery phrase accepted.", {
    account: publicAccountStatus(account, true),
    encryptedRecoveryBackup: account.encryptedRecoveryBackup || null
  });
}

async function resetPasswordWithRecovery(socket, message = {}) {
  const peerId = String(message.peerId || "").trim();
  const recoveryPhrase = normalizeRecoveryPhrase(message.recoveryPhrase);
  const password = String(message.password || "");
  const encryptedIdentityBackup = sanitizeEncryptedBackup(message.encryptedIdentityBackup);
  const publicKeyJwk = message.publicKeyJwk || null;
  const account = /^\d{6}$/.test(peerId) ? await getAccount(peerId) : null;
  if (!account?.recoveryHash || !verifyRecoveryPhrase(recoveryPhrase, account)) {
    sendAccountResponse(socket, message, false, "Code or recovery phrase is incorrect.");
    return;
  }
  if (!validPassword(password) || !encryptedIdentityBackup?.data || !publicKeyJwk) {
    sendAccountResponse(socket, message, false, "Choose a new password and recovery backup first.");
    return;
  }
  const now = new Date().toISOString();
  await revokePeerSessions(peerId);
  const updated = sanitizeAccount({
    ...account,
    ...hashPassword(password),
    publicKeyJwk,
    encryptedIdentityBackup,
    updatedAt: now
  });
  await setAccount(peerId, updated);
  await setPublicKey(peerId, publicKeyJwk);
  const sessionToken = issueSession(peerId);
  sendAccountResponse(socket, message, true, "Password reset.", {
    sessionToken,
    account: publicAccountStatus(updated, true),
    encryptedIdentityBackup: updated.encryptedIdentityBackup || null
  });
}

async function signOutAccount(socket, message = {}) {
  const peerId = String(message.peerId || socket.bypassiumId || "").trim();
  const sessionToken = String(message.sessionToken || "");
  const session = sessions.get(sessionToken);
  if (session?.peerId === peerId || await validSession(peerId, sessionToken)) await revokeSession(sessionToken);
  sendAccountResponse(socket, message, true, "Signed out.");
}

async function deleteAccount(socket, message = {}) {
  const peerId = String(message.peerId || socket.bypassiumId || "").trim();
  if (!/^\d{6}$/.test(peerId)) {
    sendAccountResponse(socket, message, false, "Choose a valid account.");
    return;
  }
  const account = await getAccount(peerId);
  if (!account?.passwordHash || !verifyPassword(String(message.password || ""), account)) {
    sendAccountResponse(socket, message, false, "Password confirmation failed.");
    return;
  }
  await deleteAccountData(peerId);
  await revokePeerSessions(peerId);
  sendAccountResponse(socket, message, true, "Account deleted.");
}

// Relays encrypted message envelopes or queues them until the receiver reconnects.
async function relayDirectMessage(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  if (!allowUserAction(socket, "message")) return;
  if (!validateContentType(socket, message)) return;

  const targetId = String(message.to || "").trim();
  if (!/^\d{6}$/.test(targetId) || !message.encrypted) {
    send(socket, { type: "error", message: "Message target or encrypted payload is invalid." });
    return;
  }

  const envelope = {
    type: "direct-message",
    messageId: message.messageId || randomUUID(),
    from: senderId,
    profile: localProfile(senderId),
    publicKeyJwk: socket.publicKeyJwk,
    encrypted: message.encrypted,
    sentAt: message.sentAt || new Date().toISOString()
  };
  const targets = clients.get(targetId);
  send(socket, {
    type: "message-status",
    messageId: envelope.messageId,
    peerId: targetId,
    status: "sent",
    updatedAt: new Date().toISOString()
  });

  if (!targets?.size) {
    await queueForDelivery(targetId, envelope, { awaitWrite: true });
    send(socket, { type: "message-queued", peerId: targetId, sentAt: envelope.sentAt, persistent: storageMode() !== "memory" });
    return;
  }

  for (const target of targets) {
    if (target !== socket && target.readyState === 1) send(target, envelope);
  }
  queueForDelivery(targetId, envelope);
  send(socket, { type: "message-relayed", messageId: envelope.messageId, peerId: targetId, sentAt: envelope.sentAt });
}

// Relays an encrypted per-conversation setting without adding it to chat history.
async function relayDirectSetting(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  if (!allowUserAction(socket, "message")) return;
  const targetId = String(message.to || "").trim();
  if (!/^\d{6}$/.test(targetId) || !message.encrypted) {
    send(socket, { type: "error", message: "Setting target or encrypted payload is invalid." });
    return;
  }
  const envelope = {
    type: "direct-setting",
    messageId: message.messageId || randomUUID(),
    from: senderId,
    profile: localProfile(senderId),
    publicKeyJwk: socket.publicKeyJwk,
    encrypted: message.encrypted,
    sentAt: message.sentAt || new Date().toISOString()
  };
  const targets = clients.get(targetId);
  if (!targets?.size) await queueForDelivery(targetId, envelope, { awaitWrite: true });
  for (const target of targets || []) {
    if (target !== socket && target.readyState === 1) send(target, envelope);
  }
  if (targets?.size) queueForDelivery(targetId, envelope);
  send(socket, { type: "setting-relayed", messageId: envelope.messageId, peerId: targetId });
}

// Relays one encrypted group message copy per recipient and queues each copy until acked.
async function relayGroupMessage(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  if (!allowUserAction(socket, "group-message")) return;
  if (!validateContentType(socket, message)) return;
  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(senderId)) {
    send(socket, { type: "error", message: "You are not a member of this group." });
    return;
  }
  const recipients = Array.isArray(message.recipients) ? message.recipients : [];
  const sentAt = message.sentAt || new Date().toISOString();
  const messageId = message.messageId || randomUUID();
  const senderProfile = localProfile(senderId);
  const deliveries = recipients.map(async (recipient) => {
    const targetId = String(recipient.to || "").trim();
    if (targetId === senderId || !group.members.includes(targetId) || !recipient.encrypted) return null;
    const envelope = {
      type: "group-message",
      messageId,
      groupId: group.id,
      groupName: group.name,
      members: group.members,
      from: senderId,
      profile: senderProfile,
      publicKeyJwk: socket.publicKeyJwk,
      encrypted: recipient.encrypted,
      sentAt
    };
    const targets = clients.get(targetId);
    if (targets?.size) {
      for (const target of targets) {
        if (target !== socket && target.readyState === 1) send(target, envelope);
      }
      queueForDelivery(targetId, envelope);
    } else {
      await queueForDelivery(targetId, envelope, { awaitWrite: true });
    }
    return targetId;
  });
  const deliveredTo = (await Promise.all(deliveries)).filter(Boolean);
  send(socket, {
    type: "message-status",
    messageId,
    groupId: group.id,
    status: "sent",
    recipientCount: deliveredTo.length,
    updatedAt: new Date().toISOString()
  });
  send(socket, { type: "message-relayed", messageId, peerId: group.id, sentAt });
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
  const pendingKey = queuedEnvelopeKey(targetId, messageId);
  cancelledQueuedEnvelopes.add(pendingKey);
  const envelope = pendingQueuedEnvelopes.get(pendingKey) || await getOfflineMessage(targetId, messageId);
  await removeOfflineMessage(targetId, messageId);
  if (envelope?.from && (envelope.type === "direct-message" || envelope.type === "group-message")) {
    sendToClient(envelope.from, {
      type: "message-status",
      messageId: envelope.messageId || messageId,
      groupId: envelope.groupId || "",
      peerId: targetId,
      status: "delivered",
      updatedAt: new Date().toISOString()
    });
  }
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
  const groupId = String(message.groupId || "").trim();
  if (groupId) {
    const group = await getGroup(groupId);
    if (!group || !group.members.includes(senderId) || !group.members.includes(targetId)) return;
  }
  const envelope = {
    type: "read-receipt",
    queueId: randomUUID(),
    from: senderId,
    groupId,
    messageId,
    readAt: message.readAt || new Date().toISOString()
  };
  sendToClient(targetId, envelope, socket);
  queueForDelivery(targetId, envelope);
}

async function relayReaction(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  const messageId = String(message.messageId || "").trim();
  const emoji = String(message.emoji || "").slice(0, 8);
  if (!messageId || !emoji) return;

  const groupId = String(message.groupId || "").trim();
  if (groupId) {
    const group = await getGroup(groupId);
    if (!group || !group.members.includes(senderId)) return;
    for (const memberId of group.members) {
      if (memberId === senderId) continue;
      const envelope = {
        type: "reaction",
        queueId: randomUUID(),
        from: senderId,
        groupId,
        messageId,
        emoji,
        active: message.active !== false,
        reactedAt: new Date().toISOString()
      };
      sendToClient(memberId, envelope, socket);
      queueForDelivery(memberId, envelope);
    }
    return;
  }

  const targetId = String(message.to || "").trim();
  if (!/^\d{6}$/.test(targetId)) return;
  const envelope = {
    type: "reaction",
    queueId: randomUUID(),
    from: senderId,
    messageId,
    emoji,
    active: message.active !== false,
    reactedAt: new Date().toISOString()
  };
  sendToClient(targetId, envelope, socket);
  queueForDelivery(targetId, envelope);
}

// Stores a user's public profile so contacts can display their current picture.
async function publishProfile(socket, profile = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const existing = await getProfile(peerId);
  const cleanProfile = sanitizeProfile({
    ...profile,
    joinedAt: existing?.joinedAt || new Date().toISOString()
  }, true);
  await setProfile(peerId, cleanProfile);
  const account = await getAccount(peerId);
  if (account) await setAccount(peerId, { ...account, profile: cleanProfile, updatedAt: new Date().toISOString() });
  await updateQuickAddDirectory(peerId, cleanProfile);
  broadcastProfileUpdate(peerId, cleanProfile);
}

// Returns a paginated, sanitized directory of customized public profiles.
async function sendQuickAddResults(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const now = Date.now();
  if (now - Number(socket.lastQuickAddRequestAt || 0) < 200) return;
  socket.lastQuickAddRequestAt = now;
  const query = String(message.query || "").trim().toLowerCase().slice(0, 50);
  const offset = Math.min(5000, Math.max(0, Number(message.offset) || 0));
  const limit = Math.min(50, Math.max(10, Number(message.limit) || 30));
  const requestedExclusions = Array.isArray(message.exclude) ? message.exclude.slice(0, 1000) : [];
  const excluded = new Set(normalizeMembers([peerId, ...requestedExclusions]));
  const entries = await getQuickAddDirectoryEntries();
  const matches = [];
  for (const { id, profile } of entries) {
    if (excluded.has(id)) continue;
    if (!isDiscoverableProfile(profile)) continue;
    if (query && !String(profile.displayName || "").toLowerCase().includes(query) && !id.includes(query)) continue;
    matches.push({
      id,
      displayName: profile.displayName || "Bypassium User",
      profilePicture: profile.profilePicture,
      joinedAt: profile.joinedAt || profile.updatedAt || "",
      status: clients.has(id) ? "online" : "offline"
    });
  }
  const results = matches.slice(offset, offset + limit);
  send(socket, {
    type: "quick-add-results",
    results,
    offset,
    nextOffset: offset + results.length,
    hasMore: offset + results.length < matches.length,
    query
  });
}

async function searchAccounts(socket, message = {}) {
  if (!allowUserAction(socket, "directory-search")) return;
  const query = String(message.query || "").trim().toLowerCase().slice(0, 50);
  const limit = Math.min(30, Math.max(5, Number(message.limit) || 18));
  if (query.length < 2) {
    send(socket, {
      type: "account-search-results",
      requestId: String(message.requestId || ""),
      ok: true,
      query,
      results: []
    });
    return;
  }

  const entries = await getQuickAddDirectoryEntries();
  const matches = [];
  for (const { id, profile } of entries) {
    if (!isDiscoverableProfile(profile)) continue;
    const score = accountSearchScore(query, id, profile.displayName || "");
    if (score === null) continue;
    matches.push({
      id,
      displayName: profile.displayName || "Bypassium User",
      profilePicture: profile.profilePicture,
      joinedAt: profile.joinedAt || profile.updatedAt || "",
      status: clients.has(id) ? "online" : "offline",
      score
    });
  }

  matches.sort((first, second) => first.score - second.score || first.displayName.localeCompare(second.displayName));
  send(socket, {
    type: "account-search-results",
    requestId: String(message.requestId || ""),
    ok: true,
    query,
    results: matches.slice(0, limit).map(({ score, ...result }) => result)
  });
}

function accountSearchScore(query, id, displayName) {
  const name = String(displayName || "").toLowerCase();
  const code = String(id || "");
  if (name.startsWith(query)) return 0;
  if (code.startsWith(query)) return 1;
  const nameIndex = name.indexOf(query);
  if (nameIndex >= 0) return 2 + nameIndex / 100;
  const codeIndex = code.indexOf(query);
  if (codeIndex >= 0) return 3 + codeIndex / 100;
  const fuzzy = subsequenceGapScore(query, name);
  return fuzzy === null ? null : 4 + fuzzy / 100;
}

function subsequenceGapScore(query, value) {
  let cursor = 0;
  let gap = 0;
  for (const char of query) {
    const index = value.indexOf(char, cursor);
    if (index === -1) return null;
    gap += index - cursor;
    cursor = index + 1;
  }
  return gap + Math.max(0, value.length - query.length) / 10;
}

async function createGroup(socket, message) {
  const creatorId = getRegisteredSender(socket);
  if (!creatorId) return;
  if (!allowUserAction(socket, "group-manage")) return;
  const members = normalizeMembers([creatorId, ...(message.members || [])]);
  const group = {
    id: randomUUID(),
    name: String(message.name || "New group").slice(0, 80),
    avatar: sanitizeProfilePicture(message.avatar),
    members,
    createdBy: creatorId,
    ownerId: creatorId,
    admins: [creatorId],
    updatedAt: new Date().toISOString()
  };
  await setGroup(group);
  broadcastGroupUpdate(group);
}

async function renameGroup(socket, message) {
  return updateGroupDetails(socket, message);
}

async function updateGroupDetails(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!allowUserAction(socket, "group-manage")) return;
  const group = await getGroup(message.groupId);
  if (!group || !canAdministerGroup(group, peerId)) {
    send(socket, { type: "error", message: "Only the group owner or an administrator can change group details." });
    return;
  }
  if (typeof message.name === "string" && message.name.trim()) {
    group.name = message.name.trim().slice(0, 80);
  }
  if (typeof message.avatar === "string") {
    group.avatar = sanitizeProfilePicture(message.avatar);
  }
  if (typeof message.memberAddLocked === "boolean") {
    group.memberAddLocked = message.memberAddLocked;
  }
  group.updatedAt = new Date().toISOString();
  await setGroup(group);
  broadcastGroupUpdate(group);
}

async function addGroupMembers(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!allowUserAction(socket, "group-manage")) return;
  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(peerId)) {
    send(socket, { type: "error", message: "Only current group members can add people." });
    return;
  }
  if (group.memberAddLocked && group.ownerId !== peerId && !(group.admins || []).includes(peerId)) {
    send(socket, { type: "error", message: "Adding members is locked for this group." });
    return;
  }
  const requestedMembers = normalizeMembers(message.members || []);
  group.members = normalizeMembers([...group.members, ...requestedMembers]);
  group.updatedAt = new Date().toISOString();
  await setGroup(group);
  broadcastGroupUpdate(group);
}

async function setGroupAdmin(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!allowUserAction(socket, "group-manage")) return;
  const group = await getGroup(message.groupId);
  const memberId = String(message.memberId || "").trim();
  if (!group || group.ownerId !== peerId || !group.members.includes(memberId) || memberId === group.ownerId) {
    send(socket, { type: "error", message: "Only the group owner can change administrator permissions." });
    return;
  }
  const admins = new Set(group.admins || []);
  if (message.isAdmin === false) admins.delete(memberId);
  else admins.add(memberId);
  admins.add(group.ownerId);
  group.admins = [...admins].filter((id) => group.members.includes(id));
  group.updatedAt = new Date().toISOString();
  await setGroup(group);
  broadcastGroupUpdate(group);
}

async function transferGroupOwnership(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!allowUserAction(socket, "group-manage")) return;
  const group = await getGroup(message.groupId);
  const memberId = String(message.memberId || "").trim();
  if (!group || group.ownerId !== peerId || !group.members.includes(memberId) || memberId === peerId) {
    send(socket, { type: "error", message: "Choose another current group member to become the owner." });
    return;
  }
  group.ownerId = memberId;
  group.admins = normalizeMembers([memberId, peerId, ...(group.admins || [])]).filter((id) => group.members.includes(id));
  group.updatedAt = new Date().toISOString();
  await setGroup(group);
  broadcastGroupUpdate(group);
}

async function removeGroupMember(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!allowUserAction(socket, "group-manage")) return;
  const group = await getGroup(message.groupId);
  const memberId = String(message.memberId || "").trim();
  if (!group || !canAdministerGroup(group, peerId) || !group.members.includes(memberId) || memberId === group.ownerId) {
    send(socket, { type: "error", message: "That member cannot be removed by this account." });
    return;
  }
  if (group.admins.includes(memberId) && group.ownerId !== peerId) {
    send(socket, { type: "error", message: "Only the owner can remove another administrator." });
    return;
  }
  group.members = group.members.filter((id) => id !== memberId);
  group.admins = group.admins.filter((id) => id !== memberId);
  group.updatedAt = new Date().toISOString();
  await setGroup(group);
  broadcastGroupUpdate(group, [memberId]);
}

async function leaveGroup(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(peerId)) return;
  if (group.ownerId === peerId && group.members.length > 1) {
    send(socket, { type: "error", message: "Transfer group ownership before leaving." });
    return;
  }
  group.members = group.members.filter((member) => member !== peerId);
  group.admins = (group.admins || []).filter((member) => member !== peerId);
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
  const queueId = String(envelope.queueId || envelope.messageId || randomUUID());
  const queuedMessage = { ...envelope, queueId, queuedAt: Date.now() };
  const serialized = JSON.stringify(queuedMessage);
  if (serialized.length > MAX_QUEUED_ENVELOPE_CHARS) {
    throw new Error("That message is too large for offline delivery. Try a smaller attachment.");
  }
  if (redis) {
    const indexKey = inboxIndexKey(targetId);
    await redis.pipeline()
      .set(queuedMessageKey(targetId, queueId), serialized, "EX", queueTtlSeconds())
      .lrem(indexKey, 0, queueId)
      .rpush(indexKey, queueId)
      .ltrim(indexKey, -maxOfflineMessagesPerUser(), -1)
      .expire(indexKey, queueTtlSeconds())
      .exec();
    return;
  }

  if (upstashRestEnabled) {
    const indexKey = inboxIndexKey(targetId);
    await upstashPipeline([
      ["SET", queuedMessageKey(targetId, queueId), serialized, "EX", queueTtlSeconds()],
      ["LREM", indexKey, 0, queueId],
      ["RPUSH", indexKey, queueId],
      ["LTRIM", indexKey, -maxOfflineMessagesPerUser(), -1],
      ["EXPIRE", indexKey, queueTtlSeconds()]
    ]);
    return;
  }

  const queue = memoryOfflineMessages.get(targetId) || [];
  const deduped = queue.filter((message) => (message.queueId || message.messageId) !== queueId);
  deduped.push(queuedMessage);
  memoryOfflineMessages.set(targetId, deduped.slice(-maxOfflineMessagesPerUser()));
}

function queueForDelivery(targetId, envelope, { awaitWrite = false } = {}) {
  const queueId = String(envelope.queueId || envelope.messageId || "");
  const pendingKey = queuedEnvelopeKey(targetId, queueId);
  pendingQueuedEnvelopes.set(pendingKey, envelope);
  const write = queueOfflineMessage(targetId, envelope)
    .then(async () => {
      if (cancelledQueuedEnvelopes.has(pendingKey)) {
        await removeOfflineMessage(targetId, queueId);
      }
    })
    .catch((error) => {
      console.error("Offline queue write failed:", error.message);
    })
    .finally(() => {
      pendingQueuedEnvelopes.delete(pendingKey);
      cancelledQueuedEnvelopes.delete(pendingKey);
    });
  return awaitWrite ? write : undefined;
}

function queuedEnvelopeKey(targetId, messageId) {
  return `${targetId}:${messageId}`;
}

// Delivers queued messages with their original sentAt time. Messages stay queued until acked.
async function deliverOfflineMessages(socket) {
  const queue = await getOfflineMessages(socket.bypassiumId);
  const legacyQueue = await getLegacyOfflineMessages(socket.bypassiumId);
  const seen = new Set();
  const expiredIds = [];
  const fresh = [];
  for (const message of [...queue, ...legacyQueue]) {
    const id = String(message.queueId || message.messageId || "");
    if (!id || seen.has(id)) continue;
    seen.add(id);
    if (Date.now() - message.queuedAt > queueTtlSeconds() * 1000) {
      expiredIds.push(id);
      continue;
    }
    fresh.push(message);
  }
  for (const message of fresh) send(socket, message);
  for (const id of expiredIds) await removeOfflineMessage(socket.bypassiumId, id);
  if (legacyQueue.length) await deleteLegacyInbox(socket.bypassiumId);
}

async function getOfflineMessages(targetId) {
  if (!redis && !upstashRestEnabled) return memoryOfflineMessages.get(targetId) || [];
  const ids = await getInboxIds(targetId);
  const uniqueIds = [...new Set(ids)].slice(-maxOfflineMessagesPerUser());
  const messages = [];
  const keptIds = [];
  for (const id of uniqueIds) {
    const stored = await getQueuedMessage(targetId, id);
    if (!stored) continue;
    try {
      messages.push(JSON.parse(stored));
      keptIds.push(id);
    } catch {
      await deleteQueuedMessage(targetId, id);
    }
  }
  if (keptIds.length !== ids.length) await replaceInboxIds(targetId, keptIds);
  return messages;
}

async function removeOfflineMessage(targetId, messageId) {
  await deleteQueuedMessage(targetId, messageId);
  await removeInboxId(targetId, messageId);
}

async function getOfflineMessage(targetId, messageId) {
  if (!redis && !upstashRestEnabled) {
    return (memoryOfflineMessages.get(targetId) || [])
      .find((message) => (message.queueId || message.messageId) === messageId) || null;
  }
  const stored = await getQueuedMessage(targetId, messageId);
  if (!stored) return null;
  try {
    return typeof stored === "string" ? JSON.parse(stored) : stored;
  } catch {
    return null;
  }
}

async function getInboxIds(targetId) {
  if (redis) {
    return redis.lrange(inboxIndexKey(targetId), 0, -1);
  }
  if (upstashRestEnabled) {
    return upstashCommand(["LRANGE", inboxIndexKey(targetId), 0, -1]);
  }
  return [];
}

async function getQueuedMessage(targetId, messageId) {
  if (redis) return redis.get(queuedMessageKey(targetId, messageId));
  if (upstashRestEnabled) return upstashCommand(["GET", queuedMessageKey(targetId, messageId)]);
  return null;
}

async function deleteQueuedMessage(targetId, messageId) {
  if (redis) {
    await redis.del(queuedMessageKey(targetId, messageId));
    return;
  }
  if (upstashRestEnabled) {
    await upstashCommand(["DEL", queuedMessageKey(targetId, messageId)]);
    return;
  }
  const queue = memoryOfflineMessages.get(targetId) || [];
  const remaining = queue.filter((message) => (message.queueId || message.messageId) !== messageId);
  if (remaining.length) memoryOfflineMessages.set(targetId, remaining);
  else memoryOfflineMessages.delete(targetId);
}

async function removeInboxId(targetId, messageId) {
  if (redis) {
    await redis.lrem(inboxIndexKey(targetId), 0, messageId);
    return;
  }
  if (upstashRestEnabled) {
    await upstashCommand(["LREM", inboxIndexKey(targetId), 0, messageId]);
  }
}

async function replaceInboxIds(targetId, ids) {
  if (redis) {
    const key = inboxIndexKey(targetId);
    await redis.del(key);
    if (ids.length) {
      await redis.rpush(key, ...ids);
      await redis.expire(key, queueTtlSeconds());
    }
    return;
  }
  if (upstashRestEnabled) {
    const key = inboxIndexKey(targetId);
    await upstashCommand(["DEL", key]);
    if (ids.length) {
      await upstashPushList(key, ids);
      await upstashCommand(["EXPIRE", key, queueTtlSeconds()]);
    }
  }
}

async function getLegacyOfflineMessages(targetId) {
  if (!redis && !upstashRestEnabled) return [];
  try {
    const stored = redis
      ? await redis.lrange(legacyInboxKey(targetId), 0, -1)
      : await upstashCommand(["LRANGE", legacyInboxKey(targetId), 0, -1]);
    return stored.map((item) => JSON.parse(item));
  } catch (error) {
    console.error("Legacy inbox read failed:", error.message);
    return [];
  }
}

async function deleteLegacyInbox(targetId) {
  if (redis) {
    await redis.del(legacyInboxKey(targetId));
    return;
  }
  if (upstashRestEnabled) await upstashCommand(["DEL", legacyInboxKey(targetId)]);
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

async function setAccount(peerId, account) {
  const clean = sanitizeAccount(account);
  memoryAccounts.set(peerId, clean);
  if (redis) await redis.set(accountKey(peerId), JSON.stringify(clean));
  if (upstashRestEnabled) await upstashCommand(["SET", accountKey(peerId), JSON.stringify(clean)]);
}

async function getAccount(peerId) {
  if (memoryAccounts.has(peerId)) return memoryAccounts.get(peerId);
  let stored = null;
  if (redis) stored = await redis.get(accountKey(peerId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", accountKey(peerId)]);
  if (!stored) return null;
  const account = sanitizeAccount(JSON.parse(stored));
  memoryAccounts.set(peerId, account);
  return account;
}

async function removeAccount(peerId) {
  memoryAccounts.delete(peerId);
  if (redis) await redis.del(accountKey(peerId));
  if (upstashRestEnabled) await upstashCommand(["DEL", accountKey(peerId)]);
}

async function deleteAccountData(peerId) {
  await Promise.all([
    removeAccount(peerId),
    removePublicKey(peerId),
    removeProfile(peerId),
    removeQuickAddProfile(peerId),
    deleteAllQueuedMessages(peerId)
  ]);
}

async function removePublicKey(peerId) {
  memoryPublicKeys.delete(peerId);
  if (redis) await redis.del(publicKeyKey(peerId));
  if (upstashRestEnabled) await upstashCommand(["DEL", publicKeyKey(peerId)]);
}

async function removeProfile(peerId) {
  memoryProfiles.delete(peerId);
  if (redis) await redis.del(profileKey(peerId));
  if (upstashRestEnabled) await upstashCommand(["DEL", profileKey(peerId)]);
}

async function removeQuickAddProfile(peerId) {
  memoryDirectory.delete(peerId);
  if (redis) {
    await redis.zrem(quickAddDirectoryKey(), peerId);
    await redis.hdel(quickAddProfilesKey(), peerId);
  }
  if (upstashRestEnabled) {
    await upstashPipeline([
      ["ZREM", quickAddDirectoryKey(), peerId],
      ["HDEL", quickAddProfilesKey(), peerId]
    ]);
  }
}

async function deleteAllQueuedMessages(peerId) {
  memoryOfflineMessages.delete(peerId);
  const ids = await getInboxIds(peerId);
  for (const id of new Set(ids)) await deleteQueuedMessage(peerId, id);
  if (redis) {
    await redis.del(inboxIndexKey(peerId));
    await redis.del(legacyInboxKey(peerId));
  }
  if (upstashRestEnabled) {
    await upstashPipeline([
      ["DEL", inboxIndexKey(peerId)],
      ["DEL", legacyInboxKey(peerId)]
    ]);
  }
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

async function updateQuickAddDirectory(peerId, profile) {
  const key = quickAddDirectoryKey();
  if (!isDiscoverableProfile(profile)) {
    memoryDirectory.delete(peerId);
    if (redis) {
      await redis.zrem(key, peerId);
      await redis.hdel(quickAddProfilesKey(), peerId);
    }
    if (upstashRestEnabled) {
      await upstashPipeline([
        ["ZREM", key, peerId],
        ["HDEL", quickAddProfilesKey(), peerId]
      ]);
    }
    return;
  }
  const joinedAt = profile.joinedAt || new Date().toISOString();
  const score = Number.isFinite(Date.parse(joinedAt)) ? Date.parse(joinedAt) : Date.now();
  memoryDirectory.set(peerId, { score, profile });
  if (redis) {
    await redis.zadd(key, score, peerId);
    await redis.hset(quickAddProfilesKey(), peerId, JSON.stringify(profile));
  }
  if (upstashRestEnabled) {
    await upstashPipeline([
      ["ZADD", key, score, peerId],
      ["HSET", quickAddProfilesKey(), peerId, JSON.stringify(profile)]
    ]);
  }
}

async function getQuickAddDirectoryEntries() {
  if (redis) {
    const ids = await redis.zrevrange(quickAddDirectoryKey(), 0, 999);
    if (!ids.length) return [];
    const stored = await redis.hmget(quickAddProfilesKey(), ...ids);
    return ids.map((id, index) => ({ id, profile: parseStoredProfile(stored[index]) })).filter((entry) => entry.profile);
  }
  if (upstashRestEnabled) {
    const ids = await upstashCommand(["ZREVRANGE", quickAddDirectoryKey(), 0, 999]);
    if (!ids.length) return [];
    const stored = await upstashCommand(["HMGET", quickAddProfilesKey(), ...ids]);
    return ids.map((id, index) => ({ id, profile: parseStoredProfile(stored[index]) })).filter((entry) => entry.profile);
  }
  return [...memoryDirectory.entries()]
    .sort((first, second) => second[1].score - first[1].score)
    .map(([id, entry]) => ({ id, profile: entry.profile }));
}

function parseStoredProfile(value) {
  try {
    return value ? sanitizeProfile(JSON.parse(value)) : null;
  } catch {
    return null;
  }
}

function isDiscoverableProfile(profile = {}) {
  if (profile.quickAddVisible === false) return false;
  const displayName = String(profile.displayName || "").trim();
  return Boolean(
    profile.profilePicture
    || (displayName && displayName.toLowerCase() !== "local user")
  );
}

async function setGroup(group) {
  const normalized = normalizeGroup(group);
  memoryGroups.set(normalized.id, normalized);
  if (redis) await redis.set(groupKey(normalized.id), JSON.stringify(normalized));
  if (upstashRestEnabled) await upstashCommand(["SET", groupKey(normalized.id), JSON.stringify(normalized)]);
}

async function getGroup(groupId) {
  const cleanGroupId = String(groupId || "").trim();
  if (!cleanGroupId) return null;
  if (memoryGroups.has(cleanGroupId)) return normalizeGroup(memoryGroups.get(cleanGroupId));
  let stored = null;
  if (redis) stored = await redis.get(groupKey(cleanGroupId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", groupKey(cleanGroupId)]);
  if (!stored) return null;
  const group = normalizeGroup(JSON.parse(stored));
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
  if (!redis && !upstashRestEnabled) return [...memoryGroups.values()].map(normalizeGroup);
  const keys = await listKeys("bypassium:group:*");
  const groups = [];
  for (const key of keys) {
    let stored = null;
    if (redis) stored = await redis.get(key);
    if (upstashRestEnabled) stored = await upstashCommand(["GET", key]);
    if (stored) groups.push(normalizeGroup(JSON.parse(stored)));
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

function normalizeGroup(group = {}) {
  const members = normalizeMembers(group.members || []);
  const preferredOwner = String(group.ownerId || group.createdBy || "").trim();
  const ownerId = members.includes(preferredOwner) ? preferredOwner : members[0] || "";
  const admins = normalizeMembers([ownerId, ...(group.admins || [])]).filter((id) => members.includes(id));
  return {
    ...group,
    members,
    ownerId,
    admins
  };
}

function canAdministerGroup(group, peerId) {
  return group.ownerId === peerId || (group.admins || []).includes(peerId);
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
  return countKeys("bypassium:inbox-index:*");
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
  const body = JSON.stringify(command);
  if (body.length > MAX_UPSTASH_COMMAND_CHARS) {
    throw new Error("Upstash command would exceed the safe request size limit.");
  }
  const response = await fetch(UPSTASH_REST_URL, {
    method: "POST",
    headers: {
      authorization: `Bearer ${UPSTASH_REST_TOKEN}`,
      "content-type": "application/json"
    },
    body
  });
  const payload = await response.json();
  if (!response.ok || payload.error) {
    throw new Error(payload.error || `Upstash command failed with ${response.status}`);
  }
  return payload.result;
}

async function upstashPipeline(commands) {
  const body = JSON.stringify(commands);
  if (body.length > MAX_UPSTASH_COMMAND_CHARS) {
    throw new Error("Upstash pipeline would exceed the safe request size limit.");
  }
  const response = await fetch(`${UPSTASH_REST_URL.replace(/\/$/, "")}/pipeline`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${UPSTASH_REST_TOKEN}`,
      "content-type": "application/json"
    },
    body
  });
  const payload = await response.json();
  const failed = Array.isArray(payload) && payload.find((result) => result?.error);
  if (!response.ok || !Array.isArray(payload) || failed) {
    throw new Error(failed?.error || payload?.error || `Upstash pipeline failed with ${response.status}`);
  }
  return payload.map((result) => result.result);
}

async function upstashPushList(key, items) {
  let chunk = [];
  let chunkSize = 0;
  for (const item of items) {
    if (chunk.length && (chunk.length >= MAX_UPSTASH_RPUSH_ITEMS || chunkSize + item.length > MAX_UPSTASH_RPUSH_CHARS)) {
      await upstashCommand(["RPUSH", key, ...chunk]);
      chunk = [];
      chunkSize = 0;
    }
    chunk.push(item);
    chunkSize += item.length;
  }
  if (chunk.length) {
    await upstashCommand(["RPUSH", key, ...chunk]);
  }
}

function storageMode() {
  if (redis) return "redis";
  if (upstashRestEnabled) return "upstash-rest";
  return "memory";
}

function sanitizeProfile(profile = {}, stampUpdate = false) {
  const cleanProfile = {
    displayName: String(profile?.displayName || "").slice(0, 80),
    profilePicture: sanitizeProfilePicture(profile?.profilePicture),
    joinedAt: String(profile?.joinedAt || "").slice(0, 40),
    quickAddVisible: profile?.quickAddVisible !== false
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

function sanitizeAccount(account = {}) {
  return {
    peerId: String(account.peerId || "").slice(0, 6),
    passwordSalt: String(account.passwordSalt || "").slice(0, 128),
    passwordHash: String(account.passwordHash || "").slice(0, 256),
    publicKeyJwk: account.publicKeyJwk || null,
    encryptedIdentityBackup: sanitizeEncryptedBackup(account.encryptedIdentityBackup),
    encryptedRecoveryBackup: sanitizeEncryptedBackup(account.encryptedRecoveryBackup),
    recoverySalt: String(account.recoverySalt || "").slice(0, 128),
    recoveryHash: String(account.recoveryHash || "").slice(0, 256),
    profile: sanitizeProfile(account.profile || {}),
    createdAt: String(account.createdAt || "").slice(0, 40),
    updatedAt: String(account.updatedAt || "").slice(0, 40)
  };
}

function sanitizeEncryptedBackup(value = null) {
  if (!value || typeof value !== "object") return null;
  return {
    version: 1,
    salt: String(value.salt || "").slice(0, 256),
    iv: String(value.iv || "").slice(0, 128),
    data: String(value.data || "").slice(0, 120000),
    kdf: String(value.kdf || "PBKDF2-SHA-256").slice(0, 40)
  };
}

function validPassword(password) {
  return password.length >= 8 && password.length <= 200;
}

function hashPassword(password) {
  const passwordSalt = randomBytes(16).toString("base64url");
  const passwordHash = scryptSync(password, passwordSalt, 32).toString("base64url");
  return { passwordSalt, passwordHash };
}

function hashRecoveryPhrase(recoveryPhrase) {
  const recoverySalt = randomBytes(16).toString("base64url");
  const recoveryHash = scryptSync(`recovery:${recoveryPhrase}`, recoverySalt, 32).toString("base64url");
  return { recoverySalt, recoveryHash };
}

function verifyPassword(password, account = {}) {
  if (!validPassword(password) || !account.passwordSalt || !account.passwordHash) return false;
  const expected = Buffer.from(account.passwordHash, "base64url");
  const actual = scryptSync(password, account.passwordSalt, 32);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function verifyRecoveryPhrase(recoveryPhrase, account = {}) {
  if (!validRecoveryPhrase(recoveryPhrase) || !account.recoverySalt || !account.recoveryHash) return false;
  const expected = Buffer.from(account.recoveryHash, "base64url");
  const actual = scryptSync(`recovery:${recoveryPhrase}`, account.recoverySalt, 32);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function normalizeRecoveryPhrase(phrase = "") {
  return String(phrase || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z\s-]/g, " ")
    .replace(/\s+/g, " ");
}

function validRecoveryPhrase(phrase = "") {
  const words = normalizeRecoveryPhrase(phrase).split(" ").filter(Boolean);
  return words.length >= 8 && words.length <= 24;
}

function samePublicKey(first, second) {
  return stableStringify(first) === stableStringify(second);
}

function stableStringify(value) {
  if (!value || typeof value !== "object") return JSON.stringify(value);
  const sorted = {};
  for (const key of Object.keys(value).sort()) sorted[key] = value[key];
  return JSON.stringify(sorted);
}

function issueSession(peerId) {
  const token = randomBytes(32).toString("base64url");
  sessions.set(token, { peerId, expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  void persistSession(token, peerId).catch((error) => console.error("Could not persist session:", error.message));
  return token;
}

async function validSession(peerId, token) {
  const cleanPeerId = String(peerId || "");
  const cleanToken = String(token || "");
  if (!/^\d{6}$/.test(cleanPeerId) || cleanToken.length < 24) return false;
  const session = sessions.get(cleanToken);
  if (session?.peerId === cleanPeerId && session.expiresAt > Date.now()) {
    session.expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
    void persistSession(cleanToken, cleanPeerId).catch((error) => console.error("Could not refresh session:", error.message));
    return true;
  }
  const stored = await getPersistedSession(cleanToken);
  if (stored?.peerId !== cleanPeerId) return false;
  sessions.set(cleanToken, { peerId: cleanPeerId, expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000 });
  void persistSession(cleanToken, cleanPeerId).catch((error) => console.error("Could not refresh session:", error.message));
  return true;
}

async function persistSession(token, peerId) {
  const payload = JSON.stringify({ peerId, createdAt: new Date().toISOString() });
  sessions.set(token, { peerId, expiresAt: Date.now() + SESSION_TTL_SECONDS * 1000 });
  if (redis) {
    await redis.set(sessionKey(token), payload, "EX", SESSION_TTL_SECONDS);
    await redis.sadd(sessionIndexKey(peerId), token);
    await redis.expire(sessionIndexKey(peerId), SESSION_TTL_SECONDS);
  }
  if (upstashRestEnabled) {
    await upstashPipeline([
      ["SET", sessionKey(token), payload, "EX", SESSION_TTL_SECONDS],
      ["SADD", sessionIndexKey(peerId), token],
      ["EXPIRE", sessionIndexKey(peerId), SESSION_TTL_SECONDS]
    ]);
  }
}

async function getPersistedSession(token) {
  let stored = null;
  if (redis) stored = await redis.get(sessionKey(token));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", sessionKey(token)]);
  if (!stored) return null;
  try {
    return JSON.parse(stored);
  } catch {
    return null;
  }
}

async function revokeSession(token) {
  const cleanToken = String(token || "");
  if (!cleanToken) return;
  const session = sessions.get(cleanToken) || await getPersistedSession(cleanToken);
  sessions.delete(cleanToken);
  if (redis) {
    await redis.del(sessionKey(cleanToken));
    if (session?.peerId) await redis.srem(sessionIndexKey(session.peerId), cleanToken);
  }
  if (upstashRestEnabled) {
    const commands = [["DEL", sessionKey(cleanToken)]];
    if (session?.peerId) commands.push(["SREM", sessionIndexKey(session.peerId), cleanToken]);
    await upstashPipeline(commands);
  }
}

async function revokePeerSessions(peerId) {
  const cleanPeerId = String(peerId || "");
  for (const [token, session] of sessions.entries()) {
    if (session.peerId === cleanPeerId) sessions.delete(token);
  }
  let tokens = [];
  if (redis) tokens = await redis.smembers(sessionIndexKey(cleanPeerId));
  if (upstashRestEnabled) tokens = await upstashCommand(["SMEMBERS", sessionIndexKey(cleanPeerId)]) || [];
  if (tokens.length) {
    const sessionKeys = tokens.map(sessionKey);
    if (redis) await redis.del(...sessionKeys);
    if (upstashRestEnabled) await upstashPipeline(sessionKeys.map((key) => ["DEL", key]));
  }
  if (redis) await redis.del(sessionIndexKey(cleanPeerId));
  if (upstashRestEnabled) await upstashCommand(["DEL", sessionIndexKey(cleanPeerId)]);
}

function publicAccountStatus(account, hasPassword = false) {
  return {
    exists: Boolean(account),
    hasPassword: Boolean(hasPassword),
    peerId: account?.peerId || "",
    profile: sanitizeProfile(account?.profile || {}),
    createdAt: account?.createdAt || "",
    updatedAt: account?.updatedAt || ""
  };
}

function sendAccountResponse(socket, message, ok, responseMessage, data = {}) {
  send(socket, {
    type: "account-response",
    requestId: String(message.requestId || ""),
    ok,
    message: responseMessage,
    ...data
  });
}

function allowUserAction(socket, action = "general") {
  return enforceSocketRateLimit(socket, action);
}

function validateContentType(socket, message = {}) {
  const attachmentBytes = Math.max(0, Number(message.attachmentBytes) || 0);
  if (attachmentBytes > MAX_QUEUED_ENVELOPE_CHARS) {
    send(socket, { type: "error", message: "That attachment is too large for offline delivery." });
    return false;
  }
  return true;
}

function enforceSocketRateLimit(socket, action = "general") {
  const now = Date.now();
  const limits = {
    message: 120,
    "group-message": 120,
    "group-manage": 40,
    "directory-search": 80,
    general: 90
  };
  const limit = limits[action] || limits.general;
  if (!socket.rateWindows) socket.rateWindows = new Map();
  const current = socket.rateWindows.get(action) || { startedAt: now, count: 0 };
  if (now - current.startedAt >= 60000) {
    current.startedAt = now;
    current.count = 0;
  }
  current.count += 1;
  socket.rateWindows.set(action, current);
  if (current.count <= limit) return true;
  send(socket, { type: "error", message: "This account is sending too quickly. Try again shortly." });
  return false;
}

function queueTtlSeconds() {
  return OFFLINE_MESSAGE_TTL_SECONDS;
}

function maxOfflineMessagesPerUser() {
  return MAX_OFFLINE_MESSAGES_PER_USER;
}

function localProfile(peerId) {
  return sanitizeProfile(memoryProfiles.get(peerId) || {});
}

function publicKeyKey(peerId) {
  return `bypassium:public-key:${peerId}`;
}

function accountKey(peerId) {
  return `bypassium:account:${peerId}`;
}

function sessionKey(token) {
  return `bypassium:session:${token}`;
}

function sessionIndexKey(peerId) {
  return `bypassium:sessions:${peerId}`;
}

function profileKey(peerId) {
  return `bypassium:profile:${peerId}`;
}

function quickAddDirectoryKey() {
  return "bypassium:quick-add-directory";
}

function quickAddProfilesKey() {
  return "bypassium:quick-add-profiles";
}

function groupKey(groupId) {
  return `bypassium:group:${groupId}`;
}

function legacyInboxKey(peerId) {
  return `bypassium:inbox:${peerId}`;
}

function inboxIndexKey(peerId) {
  return `bypassium:inbox-index:${peerId}`;
}

function queuedMessageKey(peerId, messageId) {
  return `bypassium:queued:${peerId}:${messageId}`;
}

function sendToClient(peerId, message, exceptSocket = null) {
  const sockets = clients.get(peerId);
  if (!sockets) return;
  for (const socket of sockets) {
    if (socket !== exceptSocket && socket.readyState === 1) send(socket, message);
  }
}

function send(socket, message) {
  if (socket.readyState !== 1) return;
  const serialized = JSON.stringify(message);
  socket.send(serialized);
}

server.listen(PORT, () => {
  console.log(`Bypassium message server listening on ${PORT}`);
});
