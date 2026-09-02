import http from "node:http";
import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import Redis from "ioredis";
import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 10000);
const OFFLINE_MESSAGE_TTL_SECONDS = 90 * 24 * 60 * 60;
const HISTORY_TTL_SECONDS = Number(process.env.HISTORY_TTL_SECONDS || 0);
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const ADMIN_RESET_TTL_SECONDS = 30 * 60;
const ADMIN_AUDIT_LIMIT = 500;
const SAFETY_LOG_LIMIT = 1000;
const MAX_OFFLINE_MESSAGES_PER_USER = 500;
const MAX_HISTORY_MESSAGES_PER_USER = Number(process.env.MAX_HISTORY_MESSAGES_PER_USER || 0);
const DEFAULT_HISTORY_SYNC_LIMIT = Number(process.env.DEFAULT_HISTORY_SYNC_LIMIT || 300);
const MAX_HISTORY_SYNC_LIMIT = Number(process.env.MAX_HISTORY_SYNC_LIMIT || 5000);
const MAX_PROFILE_PICTURE_CHARS = 18000;
const MAX_UPSTASH_RPUSH_ITEMS = 4;
const MAX_UPSTASH_RPUSH_CHARS = 18_000_000;
const MAX_UPSTASH_COMMAND_CHARS = 20_000_000;
const MAX_QUEUED_ENVELOPE_CHARS = 7_500_000;
const MAX_WEBSOCKET_PAYLOAD_CHARS = 20_000_000;
const MAX_HISTORY_BATCH_CHARS = 240_000;
const OFFLINE_DELIVERY_BATCH_SIZE = 6;
const BACKGROUND_DELIVERY_YIELD_MS = 8;
const MAX_CALL_SIGNAL_CHARS = 64_000;
const MAX_GROUP_CALL_MEMBERS = 5;
const GROUP_CALL_TTL_MS = 4 * 60 * 60 * 1000;
const WALLET_STARTING_BALANCE = Math.max(0, Math.round(Number(process.env.WALLET_STARTING_BALANCE || 2500)));
const WALLET_MAX_TRANSFER = Math.max(1, Math.round(Number(process.env.WALLET_MAX_TRANSFER || 100000)));
const WALLET_DAILY_TRANSFER_LIMIT = Math.max(WALLET_MAX_TRANSFER, Math.round(Number(process.env.WALLET_DAILY_TRANSFER_LIMIT || 250000)));
const WALLET_HISTORY_LIMIT = 100;
const MEMORY_REWARD_COOLDOWN_MS = 20_000;
const DEFAULT_PRICING = Object.freeze({
  attachmentUpTo256Kb: 2,
  attachmentUpTo1Mb: 5,
  attachmentUpTo5Mb: 12,
  attachmentUpTo10Mb: 20,
  attachmentOver10Mb: 35,
  directCallPerMinute: Math.max(1, Math.round(Number(process.env.CALL_BLOCK_COST || 12))),
  groupCallPerMinute: Math.max(1, Math.round(Number(process.env.GROUP_CALL_BLOCK_COST || 32))),
  directCallDailyFreeSeconds: Math.max(0, Math.round(Number(process.env.CALL_DAILY_FREE_SECONDS || 300))),
  memoryDeckFlip: 350,
  memoryUnder10Seconds: 1160,
  memoryUnder20Seconds: 960,
  memoryUnder30Seconds: 760,
  memoryUnder40Seconds: 560,
  memoryUnder50Seconds: 460,
  memoryUnder60Seconds: 360,
  memoryOver60Seconds: 260
});
let pricing = { ...DEFAULT_PRICING };
const CALL_BLOCK_SECONDS = 60;
const CALL_BILLING_TTL_SECONDS = 6 * 60 * 60;
const STORY_TTL_SECONDS = 24 * 60 * 60;
const SOCIAL_DRAFT_TTL_SECONDS = 30 * 24 * 60 * 60;
const REEL_TTL_SECONDS = 10 * 365 * 24 * 60 * 60;
const MAX_SOCIAL_ITEMS_PER_VIEWER = Math.max(1000, Number(process.env.MAX_SOCIAL_ITEMS_PER_VIEWER) || 1000);
const MAX_STORY_RECIPIENTS = 250;
const REDIS_URL = process.env.REDIS_URL || process.env.RENDER_REDIS_URL || process.env.KEY_VALUE_URL || "";
const UPSTASH_REST_URL = process.env.UPSTASH_REDIS_REST_URL || "";
const UPSTASH_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const ADMIN_HUB_IDS = new Set(String(process.env.ADMIN_HUB_IDS || "904674,907623,137096,396172,767838")
  .split(",").map((value) => value.trim()).filter((value) => /^\d{6}$/.test(value)));
const clients = new Map();
const sessions = new Map();
const memoryPublicKeys = new Map();
const memoryProfiles = new Map();
const memoryAccounts = new Map();
const memoryAccountIndex = new Set();
const memoryAccountSearch = new Map();
const memoryRestrictions = new Map();
const memoryOwnerResetCodes = new Map();
const memoryAdminAudit = [];
const memorySafetyLog = [];
const memoryDirectory = new Map();
const memoryGroups = new Map();
const memoryContactLists = new Map();
const memoryOfflineMessages = new Map();
const memoryHistoryMessages = new Map();
const memoryConversationReadStates = new Map();
const memoryStories = new Map();
const memoryStoryIndexes = new Map();
const memoryStoryViews = new Map();
const memoryStoryReactions = new Map();
const memoryStoryComments = new Map();
const memoryStoryShares = new Map();
const memorySocialDrafts = new Map();
const memoryWallets = new Map();
const memoryWalletTransactions = new Map();
const memoryWalletIndexes = new Map();
const memoryWalletDailySpend = new Map();
const memoryArcadeRounds = new Map();
const memoryArcadeCooldowns = new Map();
const memoryCallBilling = new Map();
const memoryCallFreeUsage = new Map();
const PRICING_STORAGE_KEY = "bypassium:pricing:v1";
let walletOperationQueue = Promise.resolve();
let memoryAdminHubState = null;
const adminHubTyping = new Map();
const pendingQueuedEnvelopes = new Map();
const cancelledQueuedEnvelopes = new Set();
const groupCallRooms = new Map();
let supportBotStatus = null;
let accountIndexHydrated = false;
let accountIndexHydrationPromise = null;
const redis = createRedisClient();
const upstashRestEnabled = Boolean(!redis && UPSTASH_REST_URL && UPSTASH_REST_TOKEN);

const server = http.createServer(async (request, response) => {
  const corsHeaders = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, x-admin-token, x-bypassium-id"
  };
  if (request.method === "OPTIONS") {
    response.writeHead(204, corsHeaders);
    response.end();
    return;
  }

  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

  if (url.pathname === "/health") {
    const supportBotId = String(process.env.BOT_PEER_ID || "").trim();
    const supportBotConfigured = /^\d{6}$/.test(supportBotId)
      && Boolean(process.env.BOT_PASSWORD)
      && Boolean(process.env.GROQ_API_KEY || process.env.OPENAI_API_KEY);
    response.writeHead(200, { ...corsHeaders, "content-type": "application/json" });
    response.end(JSON.stringify({
      ok: true,
      storage: storageMode(),
      onlineClients: clients.size,
      supportBotConfigured,
      supportBotOnline: supportBotConfigured && Boolean(clients.get(supportBotId)?.size),
      supportBot: supportBotConfigured ? supportBotStatus : null,
      uptimeSeconds: Math.round(process.uptime())
    }));
    return;
  }

  if (url.pathname === "/admin") {
    response.writeHead(200, {
      ...corsHeaders,
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store"
    });
    response.end(adminPageHtml());
    return;
  }

  if (url.pathname.startsWith("/admin/api/")) {
    await handleAdminApi(request, response, url, corsHeaders);
    return;
  }

  if (url.pathname.startsWith("/admin-hub/api/")) {
    await handleAdminHubApi(request, response, url, corsHeaders);
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
      if (message.type === "check-owner-reset-code") await checkOwnerResetCode(socket, message);
      if (message.type === "reset-password-with-recovery") await resetPasswordWithRecovery(socket, message);
      if (message.type === "reset-password-with-owner-code") await resetPasswordWithOwnerCode(socket, message);
      if (message.type === "sign-out") await signOutAccount(socket, message);
      if (message.type === "delete-account") await deleteAccount(socket, message);
      if (message.type === "watch-contacts") await sendContactStatuses(socket, message.contacts);
      if (message.type === "contacts-sync") await syncContacts(socket, message);
      if (message.type === "contacts-sync-request") await sendSyncedContacts(socket);
      if (message.type === "contacts-delete") await deleteSyncedContact(socket, message);
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
      if (message.type === "read-state") await relayReadState(socket, message);
      if (message.type === "reaction") await relayReaction(socket, message);
      if (message.type === "group-call-start") await startGroupCall(socket, message);
      if (message.type === "group-call-join") await joinGroupCall(socket, message);
      if (message.type === "group-call-leave") await leaveGroupCall(socket, message);
      if (message.type === "call-signal") await relayCallSignal(socket, message);
      if (message.type === "history-sync") await syncHistoryMessages(socket, message);
      if (message.type === "history-backfill") await backfillHistoryMessages(socket, message);
      if (message.type === "story-publish") await publishStory(socket, message);
      if (message.type === "story-sync") await syncStories(socket);
      if (message.type === "story-view") await viewStory(socket, message);
      if (message.type === "story-feedback") await submitStoryFeedback(socket, message);
      if (message.type === "story-share") await recordStoryShare(socket, message);
      if (message.type === "story-delete") await deleteStory(socket, message);
      if (message.type === "story-watch") await recordStoryWatch(socket, message);
      if (message.type === "draft-save") await saveSocialDraft(socket, message);
      if (message.type === "draft-sync") await syncSocialDrafts(socket, message);
      if (message.type === "draft-delete") await deleteSocialDraft(socket, message);
      if (message.type === "wallet-sync") await syncWallet(socket, message);
      if (message.type === "wallet-pay") await payWalletUser(socket, message);
      if (message.type === "call-billing-start") await startCallBilling(socket, message);
      if (message.type === "call-billing-top-up") await topUpCallBilling(socket, message);
      if (message.type === "call-billing-sync") await syncCallBilling(socket, message);
      if (message.type === "arcade-round-start") await startArcadeRound(socket, message);
      if (message.type === "arcade-reward") await claimArcadeReward(socket, message);
      if (message.type === "arcade-purchase") await purchaseArcadeItem(socket, message);
      if (message.type === "support-bot-status") updateSupportBotStatus(socket, message.status);
      if (message.type === "support-bot-inbox-sync") await syncSupportBotInbox(socket);
      if (message.type === "sync") await syncClient(socket);
    } catch (error) {
      console.error("Message handler failed:", error.message);
      if (message?.type === "direct-message" || message?.type === "group-message") {
        send(socket, {
          type: "message-error",
          messageId: String(message.messageId || ""),
          groupId: String(message.groupId || ""),
          peerId: String(message.to || message.groupId || ""),
          message: "The message could not be stored. Retry it in a moment."
        });
      } else {
        send(socket, { type: "error", message: "The message server could not process that request. Try again in a moment." });
      }
    }
  });

  socket.on("close", () => unregisterClient(socket));
});

function updateSupportBotStatus(socket, status = {}) {
  const supportBotId = String(process.env.BOT_PEER_ID || "").trim();
  if (!supportBotId || socket.bypassiumId !== supportBotId) return;
  supportBotStatus = {
    directReplies: Math.max(0, Math.round(Number(status.directReplies) || 0)),
    groupReplies: Math.max(0, Math.round(Number(status.groupReplies) || 0)),
    ignored: Math.max(0, Math.round(Number(status.ignored) || 0)),
    errors: Math.max(0, Math.round(Number(status.errors) || 0)),
    lastError: String(status.lastError || "").slice(0, 240),
    lastIncomingAt: String(status.lastIncomingAt || "").slice(0, 40),
    lastReplyAt: String(status.lastReplyAt || "").slice(0, 40),
    lastIgnoredReason: String(status.lastIgnoredReason || "").replace(/\b\d{6}\b/g, "account").slice(0, 120),
    reportedAt: new Date().toISOString()
  };
}

// Gives the first-party Support bot a cheap durable-inbox poll without sending
// the full account, group, contact and presence sync every few seconds.
async function syncSupportBotInbox(socket) {
  const supportBotId = String(process.env.BOT_PEER_ID || "").trim();
  if (!supportBotId || socket.bypassiumId !== supportBotId) return;
  await deliverOfflineMessages(socket);
}

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

async function handleAdminApi(request, response, url, corsHeaders) {
  try {
    if (url.pathname === "/admin/api/config") {
      sendJson(response, 200, { ok: true, adminEnabled: Boolean(ADMIN_TOKEN) }, corsHeaders);
      return;
    }
    if (!adminAuthorized(request)) {
      sendJson(response, ADMIN_TOKEN ? 401 : 503, {
        ok: false,
        message: ADMIN_TOKEN ? "Admin token is missing or incorrect." : "Set ADMIN_TOKEN on the server before using the admin panel."
      }, corsHeaders);
      return;
    }

    if (request.method === "GET" && url.pathname === "/admin/api/status") {
      sendJson(response, 200, {
        ok: true,
        storage: storageMode(),
        onlineClients: clients.size,
        accounts: (await getKnownPeerIds()).length,
        groups: await countGroups(),
        queuedUsers: await countQueuedUsers(),
        auditEntries: (await getAdminAudit()).length,
        safetyEntries: (await getSafetyLog()).length
      }, corsHeaders);
      return;
    }

    if (request.method === "GET" && url.pathname === "/admin/api/accounts") {
      const query = String(url.searchParams.get("q") || "");
      const accounts = await searchAdminAccounts(query, 80);
      sendJson(response, 200, { ok: true, accounts }, corsHeaders);
      return;
    }

    if (request.method === "GET" && url.pathname === "/admin/api/account") {
      const peerId = cleanPeerId(url.searchParams.get("peerId"));
      const account = peerId ? await adminAccountDetail(peerId) : null;
      sendJson(response, account ? 200 : 404, account ? { ok: true, account } : { ok: false, message: "Account not found." }, corsHeaders);
      return;
    }

    if (request.method === "GET" && url.pathname === "/admin/api/groups") {
      const query = String(url.searchParams.get("q") || "");
      const groups = await searchAdminGroups(query, 80);
      sendJson(response, 200, { ok: true, groups }, corsHeaders);
      return;
    }

    if (request.method === "GET" && url.pathname === "/admin/api/group") {
      const groupId = cleanAdminGroupId(url.searchParams.get("groupId"));
      const group = groupId ? await adminGroupDetail(groupId) : null;
      sendJson(response, group ? 200 : 404, group ? { ok: true, group } : { ok: false, message: "Group not found." }, corsHeaders);
      return;
    }

    if (request.method === "GET" && url.pathname === "/admin/api/audit") {
      sendJson(response, 200, { ok: true, audit: await getAdminAudit() }, corsHeaders);
      return;
    }

    if (request.method === "GET" && url.pathname === "/admin/api/pricing") {
      sendJson(response, 200, { ok: true, pricing: publicPricing() }, corsHeaders);
      return;
    }

    if (request.method !== "POST") {
      sendJson(response, 405, { ok: false, message: "Method not allowed." }, corsHeaders);
      return;
    }

    const body = await readRequestJson(request);

    if (url.pathname === "/admin/api/pricing") {
      const next = await savePricingConfig(body.pricing || body);
      await recordAdminAudit("pricing-update", "", next);
      broadcastPricingUpdated();
      sendJson(response, 200, { ok: true, pricing: publicPricing(), message: "Pricing saved and sent to connected users." }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/group-update") {
      const group = await adminGroupOrError(response, corsHeaders, body.groupId);
      if (!group) return;
      const previous = { name: group.name, avatar: group.avatar, memberAddLocked: Boolean(group.memberAddLocked) };
      if (typeof body.name === "string") group.name = sanitizeGroupName(body.name, group.name || "Group chat");
      if (body.removeAvatar) group.avatar = "";
      else if (typeof body.avatar === "string" && body.avatar) group.avatar = sanitizeProfilePicture(body.avatar);
      if (typeof body.memberAddLocked === "boolean") group.memberAddLocked = body.memberAddLocked;
      group.updatedAt = new Date().toISOString();
      await setGroup(group);
      broadcastGroupUpdate(group);
      await recordAdminAudit("group-update", "", {
        groupId: group.id,
        nameChanged: previous.name !== group.name,
        avatarChanged: previous.avatar !== group.avatar,
        memberAddLockedChanged: previous.memberAddLocked !== Boolean(group.memberAddLocked)
      });
      sendJson(response, 200, { ok: true, group: await adminGroupDetail(group.id) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/group-add-members") {
      const group = await adminGroupOrError(response, corsHeaders, body.groupId);
      if (!group) return;
      const requested = Array.isArray(body.members) ? body.members : String(body.members || "").split(/[^0-9]+/);
      const additions = normalizeMembers(requested).filter((memberId) => !group.members.includes(memberId));
      if (!additions.length) {
        sendJson(response, 400, { ok: false, message: "Enter at least one new 6-digit member code." }, corsHeaders);
        return;
      }
      group.members = normalizeMembers([...group.members, ...additions]);
      group.admins = normalizeMembers([group.ownerId, ...(group.admins || [])]).filter((memberId) => group.members.includes(memberId));
      group.updatedAt = new Date().toISOString();
      await setGroup(group);
      broadcastGroupUpdate(group, additions);
      await recordAdminAudit("group-add-members", "", { groupId: group.id, additions });
      sendJson(response, 200, { ok: true, group: await adminGroupDetail(group.id) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/group-set-admin") {
      const group = await adminGroupOrError(response, corsHeaders, body.groupId);
      if (!group) return;
      const memberId = cleanPeerId(body.memberId);
      if (!memberId || !group.members.includes(memberId)) {
        sendJson(response, 400, { ok: false, message: "Choose a current group member." }, corsHeaders);
        return;
      }
      if (memberId === group.ownerId && body.isAdmin === false) {
        sendJson(response, 400, { ok: false, message: "The owner must stay an admin." }, corsHeaders);
        return;
      }
      const admins = new Set(group.admins || []);
      if (body.isAdmin === false) admins.delete(memberId);
      else admins.add(memberId);
      admins.add(group.ownerId);
      group.admins = [...admins].filter((adminId) => group.members.includes(adminId));
      group.updatedAt = new Date().toISOString();
      await setGroup(group);
      broadcastGroupUpdate(group);
      await recordAdminAudit("group-set-admin", "", { groupId: group.id, memberId, isAdmin: body.isAdmin !== false });
      sendJson(response, 200, { ok: true, group: await adminGroupDetail(group.id) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/group-transfer-owner") {
      const group = await adminGroupOrError(response, corsHeaders, body.groupId);
      if (!group) return;
      const memberId = cleanPeerId(body.memberId);
      if (!memberId || !group.members.includes(memberId)) {
        sendJson(response, 400, { ok: false, message: "Choose a current group member." }, corsHeaders);
        return;
      }
      const previousOwner = group.ownerId;
      group.ownerId = memberId;
      group.admins = normalizeMembers([memberId, previousOwner, ...(group.admins || [])]).filter((adminId) => group.members.includes(adminId));
      group.updatedAt = new Date().toISOString();
      await setGroup(group);
      broadcastGroupUpdate(group);
      await recordAdminAudit("group-transfer-owner", "", { groupId: group.id, previousOwner, newOwner: memberId });
      sendJson(response, 200, { ok: true, group: await adminGroupDetail(group.id) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/group-remove-member") {
      const group = await adminGroupOrError(response, corsHeaders, body.groupId);
      if (!group) return;
      const memberId = cleanPeerId(body.memberId);
      if (!memberId || !group.members.includes(memberId)) {
        sendJson(response, 400, { ok: false, message: "Choose a current group member." }, corsHeaders);
        return;
      }
      const previousOwner = group.ownerId;
      const previousMembers = [...group.members];
      group.members = group.members.filter((id) => id !== memberId);
      group.admins = (group.admins || []).filter((id) => id !== memberId && group.members.includes(id));
      if (!group.members.length) {
        await deleteGroup(group.id);
        broadcastGroupUpdate({ ...group, members: [], admins: [], deleted: true, updatedAt: new Date().toISOString() }, previousMembers);
        await recordAdminAudit("group-delete-empty", "", { groupId: group.id, removedMember: memberId, previousOwner });
        sendJson(response, 200, { ok: true, deleted: true, message: "Group deleted because no members remain." }, corsHeaders);
        return;
      }
      if (!group.members.includes(group.ownerId)) {
        group.ownerId = group.admins[0] || group.members[0];
      }
      group.admins = normalizeMembers([group.ownerId, ...group.admins]).filter((adminId) => group.members.includes(adminId));
      group.updatedAt = new Date().toISOString();
      await setGroup(group);
      broadcastGroupUpdate(group, [memberId]);
      await recordAdminAudit("group-remove-member", "", { groupId: group.id, memberId, previousOwner, newOwner: group.ownerId });
      sendJson(response, 200, { ok: true, group: await adminGroupDetail(group.id) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/delete-group") {
      const group = await adminGroupOrError(response, corsHeaders, body.groupId);
      if (!group) return;
      const confirm = String(body.confirm || "").trim();
      if (confirm !== group.id && confirm !== group.name) {
        sendJson(response, 400, { ok: false, message: "Type the exact group ID or group name to confirm deletion." }, corsHeaders);
        return;
      }
      const previousMembers = [...group.members];
      await deleteGroup(group.id);
      broadcastGroupUpdate({ ...group, members: [], admins: [], deleted: true, updatedAt: new Date().toISOString() }, previousMembers);
      await recordAdminAudit("delete-group", "", { groupId: group.id, name: group.name, memberCount: previousMembers.length });
      sendJson(response, 200, { ok: true, deleted: true, message: "Group deleted." }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/bulk-delete-accounts") {
      const peerIds = normalizeMembers(Array.isArray(body.peerIds) ? body.peerIds : []).slice(0, 100);
      if (!peerIds.length) {
        sendJson(response, 400, { ok: false, message: "Select at least one account to delete." }, corsHeaders);
        return;
      }
      const results = [];
      for (const id of peerIds) results.push(await deleteAccountBySupport(id));
      const cleaned = results.filter((item) => item.cleaned).map((item) => item.peerId);
      const missing = results.filter((item) => item.cleaned && !item.existed).map((item) => item.peerId);
      const failed = results.filter((item) => !item.cleaned).map((item) => item.peerId);
      await recordAdminAudit("bulk-delete-accounts", "", { count: cleaned.length, peerIds: cleaned, missing, failed });
      sendJson(response, failed.length ? 500 : 200, {
        ok: failed.length === 0,
        deleted: cleaned,
        missing,
        failed,
        message: failed.length
          ? `Could not fully delete ${failed.length} account(s).`
          : `Deleted ${cleaned.length} account(s).`
      }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/wallet-adjust") {
      const walletPeerId = cleanPeerId(body.peerId);
      const delta = Number(body.delta);
      const reason = String(body.reason || "").replace(/\s+/g, " ").trim().slice(0, 240);
      if (!walletPeerId || !Number.isSafeInteger(delta) || delta === 0 || Math.abs(delta) > 1_000_000 || !reason) {
        sendJson(response, 400, { ok: false, message: "Choose an account, enter a whole non-zero amount, and provide a reason." }, corsHeaders);
        return;
      }
      const transaction = await adjustWalletByAdmin(walletPeerId, delta, reason);
      await recordAdminAudit("wallet-adjust", walletPeerId, { delta, reason, transactionId: transaction.transactionId });
      notifyWalletUpdated(walletPeerId, transaction);
      sendJson(response, 200, { ok: true, wallet: await walletSummary(walletPeerId), transaction }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/wallet-freeze") {
      const walletPeerId = cleanPeerId(body.peerId);
      const frozen = Boolean(body.frozen);
      const reason = String(body.reason || "").replace(/\s+/g, " ").trim().slice(0, 240);
      if (!walletPeerId || !reason) {
        sendJson(response, 400, { ok: false, message: "Choose an account and provide a reason." }, corsHeaders);
        return;
      }
      await setWalletFrozen(walletPeerId, frozen, reason);
      await recordAdminAudit(frozen ? "wallet-freeze" : "wallet-unfreeze", walletPeerId, { reason });
      notifyWalletUpdated(walletPeerId);
      sendJson(response, 200, { ok: true, wallet: await walletSummary(walletPeerId) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/wallet-reverse") {
      const transactionId = String(body.transactionId || "").trim().slice(0, 100);
      const reason = String(body.reason || "").replace(/\s+/g, " ").trim().slice(0, 240);
      if (!transactionId || !reason) {
        sendJson(response, 400, { ok: false, message: "Choose a transaction and provide a reversal reason." }, corsHeaders);
        return;
      }
      const reversal = await reverseWalletTransaction(transactionId, reason);
      await recordAdminAudit("wallet-reverse", reversal.recipientId || reversal.senderId || "", { transactionId, reversalId: reversal.transactionId, reason });
      if (/^\d{6}$/.test(reversal.senderId)) void notifyWalletUpdated(reversal.senderId, reversal);
      if (/^\d{6}$/.test(reversal.recipientId)) void notifyWalletUpdated(reversal.recipientId, reversal);
      sendJson(response, 200, { ok: true, transaction: reversal }, corsHeaders);
      return;
    }

    const peerId = cleanPeerId(body.peerId);
    if (!peerId && url.pathname !== "/admin/api/audit") {
      sendJson(response, 400, { ok: false, message: "Choose a valid 6-digit account code." }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/ban") {
      const reason = String(body.reason || "Admin ban").slice(0, 240);
      const bannedUntil = normalizeAdminDate(body.bannedUntil);
      const restriction = await setAccountRestriction(peerId, {
        banned: true,
        banReason: reason,
        bannedAt: new Date().toISOString(),
        bannedUntil,
        passwordResetRequired: false
      });
      await revokePeerSessions(peerId);
      disconnectPeer(peerId, accountBanMessage(restriction), accountBanPayload(peerId, restriction));
      await recordAdminAudit("ban-account", peerId, { reason, bannedUntil });
      sendJson(response, 200, { ok: true, account: await adminAccountDetail(peerId) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/unban") {
      await setAccountRestriction(peerId, {
        banned: false,
        banReason: "",
        bannedUntil: "",
        bannedAt: ""
      });
      await recordAdminAudit("unban-account", peerId);
      sendJson(response, 200, { ok: true, account: await adminAccountDetail(peerId) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/restrictions") {
      await setAccountRestriction(peerId, {
        sendDisabled: Boolean(body.sendDisabled),
        groupsDisabled: Boolean(body.groupsDisabled),
        quickAddHidden: Boolean(body.quickAddHidden)
      });
      if (body.quickAddHidden) await removeQuickAddProfile(peerId);
      else {
        const profile = await getProfile(peerId);
        if (profile) await updateQuickAddDirectory(peerId, profile);
      }
      await recordAdminAudit("update-restrictions", peerId, {
        sendDisabled: Boolean(body.sendDisabled),
        groupsDisabled: Boolean(body.groupsDisabled),
        quickAddHidden: Boolean(body.quickAddHidden)
      });
      sendJson(response, 200, { ok: true, account: await adminAccountDetail(peerId) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/profile") {
      const account = await getAccount(peerId);
      const currentProfile = sanitizeProfile(account?.profile || await getProfile(peerId) || {});
      const displayName = String(body.displayName || "").trim().slice(0, 80) || "Bypassium User";
      const profilePicture = body.removeProfilePicture ? "" : sanitizeProfilePicture(body.profilePicture || currentProfile.profilePicture);
      const badge = sanitizeProfileBadge(body.badge);
      const cleanProfile = sanitizeProfile({
        ...currentProfile,
        displayName,
        profilePicture,
        badge
      }, true);
      await setProfile(peerId, cleanProfile);
      if (account) await setAccount(peerId, { ...account, profile: cleanProfile, updatedAt: new Date().toISOString() });
      if (await accountQuickAddHidden(peerId)) await removeQuickAddProfile(peerId);
      else await updateQuickAddDirectory(peerId, cleanProfile);
      broadcastProfileUpdate(peerId, cleanProfile);
      await recordAdminAudit("moderate-profile", peerId, {
        displayName,
        profilePictureChanged: profilePicture !== currentProfile.profilePicture,
        badgeChanged: badge !== currentProfile.badge
      });
      sendJson(response, 200, { ok: true, account: await adminAccountDetail(peerId) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/revoke-sessions") {
      await revokePeerSessions(peerId);
      disconnectPeer(peerId, "Your sessions were revoked by support.");
      await recordAdminAudit("revoke-sessions", peerId);
      sendJson(response, 200, { ok: true, account: await adminAccountDetail(peerId) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/force-reset") {
      const reset = await createOwnerResetCode(peerId);
      await revokePeerSessions(peerId);
      await setAccountRestriction(peerId, { passwordResetRequired: true, resetRequestedAt: new Date().toISOString() });
      disconnectPeer(peerId, "Support started a password reset for this account.");
      await recordAdminAudit("force-password-reset", peerId, { expiresAt: reset.expiresAt });
      sendJson(response, 200, { ok: true, resetCode: reset.code, expiresAt: reset.expiresAt, account: await adminAccountDetail(peerId) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/clear-queue") {
      await deleteAllQueuedMessages(peerId);
      await recordAdminAudit("clear-offline-queue", peerId);
      sendJson(response, 200, { ok: true, account: await adminAccountDetail(peerId) }, corsHeaders);
      return;
    }

    if (url.pathname === "/admin/api/delete-account") {
      if (String(body.confirm || "") !== peerId) {
        sendJson(response, 400, { ok: false, message: "Type the exact 6-digit code to confirm account deletion." }, corsHeaders);
        return;
      }
      const result = await deleteAccountBySupport(peerId);
      await recordAdminAudit("delete-account", peerId, { existed: result.existed, cleaned: result.cleaned });
      sendJson(response, result.cleaned ? 200 : 500, {
        ok: result.cleaned,
        deleted: result.cleaned ? [peerId] : [],
        missing: result.existed ? [] : [peerId],
        failed: result.cleaned ? [] : [peerId],
        message: result.cleaned
          ? result.existed ? "Account deleted." : "Account was already gone; stale admin entries were cleaned."
          : "Could not fully delete that account."
      }, corsHeaders);
      return;
    }

    sendJson(response, 404, { ok: false, message: "Unknown admin endpoint." }, corsHeaders);
  } catch (error) {
    console.error("Admin API failed:", error.message);
    sendJson(response, 500, { ok: false, message: error.message || "Admin request failed." }, corsHeaders);
  }
}

function adminAuthorized(request) {
  if (!ADMIN_TOKEN) return false;
  const header = String(request.headers.authorization || "");
  const bearer = header.toLowerCase().startsWith("bearer ") ? header.slice(7).trim() : "";
  const token = bearer || String(request.headers["x-admin-token"] || "");
  return safeEqualString(token, ADMIN_TOKEN);
}

const ADMIN_HUB_SECTIONS = {
  owen: { label: "Owen", ownerIds: ["907623", "137096"] },
  riley: { label: "Riley", ownerIds: ["396172"] },
  coen: { label: "Coen", ownerIds: ["904674"] },
  bypassium: { label: "Bypassium Admin", ownerIds: ["767838"] },
  shared: { label: "Shared", ownerIds: [] }
};

async function handleAdminHubApi(request, response, url, corsHeaders) {
  try {
    if (request.method === "POST" && url.pathname === "/admin-hub/api/sign-in") {
      const body = await readRequestJson(request);
      const peerId = String(body.peerId || "").trim();
      const password = String(body.password || "");
      if (!ADMIN_HUB_IDS.has(peerId)) {
        sendJson(response, 403, { ok: false, message: "This Bypassium account does not have admin access." }, corsHeaders);
        return;
      }
      const account = await getAccount(peerId);
      if (!account?.passwordHash || !verifyPassword(password, account)) {
        sendJson(response, 401, { ok: false, message: "Code or password is incorrect." }, corsHeaders);
        return;
      }
      const token = issueSession(peerId);
      const profile = await getProfile(peerId) || account.profile || {};
      sendJson(response, 200, { ok: true, token, user: adminHubUser(peerId, profile) }, corsHeaders);
      return;
    }

    const peerId = String(request.headers["x-bypassium-id"] || "").trim();
    const token = String(request.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
    if (!ADMIN_HUB_IDS.has(peerId) || !(await validSession(peerId, token))) {
      sendJson(response, 401, { ok: false, message: "Your admin session expired. Sign in again." }, corsHeaders);
      return;
    }
    const accountBlock = await accountBlockInfo(peerId, "account");
    if (accountBlock) {
      sendJson(response, 403, { ok: false, message: accountBlock.message }, corsHeaders);
      return;
    }

    if (request.method === "GET" && url.pathname === "/admin-hub/api/state") {
      const state = await getAdminHubState();
      const admins = await Promise.all([...ADMIN_HUB_IDS].map(adminHubUserFromId));
      sendJson(response, 200, {
        ok: true,
        state: visibleAdminHubState(state, peerId),
        user: await adminHubUserFromId(peerId),
        admins
      }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/updates") {
      const body = await readRequestJson(request);
      const version = String(body.version || "").trim().replace(/^v/i, "").slice(0, 24);
      if (!/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(version)) throw new Error("Use a version like 5.5.8.");
      const state = await getAdminHubState();
      state.updates ||= [];
      const existing = state.updates.find((item) => item.version === version);
      if (body.remove === true) {
        if (!existing) throw new Error("That version does not have release notes.");
        state.updates = state.updates.filter((item) => item.version !== version);
      } else {
        const description = String(body.description || "").trim().slice(0, 5000);
        if (!description) throw new Error("Write an update description first.");
        const now = new Date().toISOString();
        if (existing) {
          existing.description = description;
          existing.updatedAt = now;
          existing.updatedBy = peerId;
        } else {
          state.updates.push({ id: randomUUID(), version, description, createdAt: now, createdBy: peerId, updatedAt: now, updatedBy: peerId });
        }
        state.updates = state.updates.slice(-100);
      }
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/chat") {
      const body = await readRequestJson(request);
      const text = String(body.text || "").trim().slice(0, 2000);
      let attachment = null;
      if (body.attachment?.dataUrl) {
        const dataUrl = String(body.attachment.dataUrl || "");
        if (!/^data:(?:image\/|application\/pdf)/i.test(dataUrl)) throw new Error("Admin Chat supports images and PDFs.");
        if (dataUrl.length > 500_000) throw new Error("Keep chat attachments under about 350 KB.");
        attachment = { name: String(body.attachment.name || "Attachment").slice(0, 120), type: String(body.attachment.type || ""), dataUrl };
      }
      if (!text && !attachment) throw new Error("Write a message or attach a file first.");
      const state = await getAdminHubState();
      const mentions = findAdminHubMentions(text);
      const replyTo = state.chat.find((item) => item.id === body.replyTo)?.id || "";
      state.chat.push({ id: randomUUID(), clientId: String(body.clientId || "").slice(0, 80), authorId: peerId, text, attachment, replyTo, mentions, reactions: {}, editedAt: "", createdAt: new Date().toISOString() });
      state.chat = state.chat.slice(-150);
      let retainedAttachmentChars = 0;
      for (let index = state.chat.length - 1; index >= 0; index -= 1) {
        const chatAttachment = state.chat[index].attachment;
        if (!chatAttachment?.dataUrl) continue;
        retainedAttachmentChars += chatAttachment.dataUrl.length;
        if (retainedAttachmentChars > 4_000_000) state.chat[index].attachment = { ...chatAttachment, dataUrl: "", expired: true };
      }
      adminHubTyping.delete(peerId);
      addAdminHubNotifications(state, mentions, peerId, "chat", "", "You were mentioned in Admin Chat.");
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/chat-action") {
      const body = await readRequestJson(request);
      const state = await getAdminHubState();
      const message = state.chat.find((item) => item.id === body.messageId);
      if (!message) throw new Error("Message not found.");
      if (body.action === "delete") {
        if (message.authorId !== peerId) throw new Error("You can only delete your own message.");
        state.chat = state.chat.filter((item) => item.id !== message.id);
      } else if (body.action === "edit") {
        if (message.authorId !== peerId) throw new Error("You can only edit your own message.");
        const text = String(body.text || "").trim().slice(0, 2000);
        if (!text) throw new Error("The edited message cannot be empty.");
        message.text = text;
        message.mentions = findAdminHubMentions(text);
        message.editedAt = new Date().toISOString();
      } else if (body.action === "react") {
        const emoji = ["👍", "❤️", "🔥", "😂", "👀", "✅"].includes(body.emoji) ? body.emoji : "";
        if (!emoji) throw new Error("Choose a supported reaction.");
        message.reactions ||= {};
        message.reactions[emoji] ||= [];
        message.reactions[emoji] = message.reactions[emoji].includes(peerId) ? message.reactions[emoji].filter((id) => id !== peerId) : [...message.reactions[emoji], peerId];
      } else throw new Error("Unknown chat action.");
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/typing") {
      const body = await readRequestJson(request);
      if (body.typing === true) adminHubTyping.set(peerId, Date.now() + 5000);
      else adminHubTyping.delete(peerId);
      sendJson(response, 200, { ok: true }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/board") {
      const body = await readRequestJson(request);
      const section = String(body.section || "");
      const state = await getAdminHubState();
      const current = state.boards[section];
      if (!current || !canEditAdminBoard(section, current, peerId)) {
        sendJson(response, 403, { ok: false, message: "You do not have permission to edit this board." }, corsHeaders);
        return;
      }
      const collaborators = Array.isArray(body.collaborators)
        ? [...new Set(body.collaborators.map(String).filter((id) => ADMIN_HUB_IDS.has(id) && id !== peerId))]
        : current.collaborators;
      const isPublishing = body.published === true;
      state.boards[section] = {
        ...current,
        title: String(body.title || current.title).trim().slice(0, 100) || current.title,
        contentHtml: sanitizeAdminHubHtml(body.contentHtml),
        mentions: findAdminHubMentions(String(body.contentHtml || "").replace(/<[^>]+>/g, " ")),
        collaborators,
        published: isPublishing,
        publishedAt: isPublishing ? new Date().toISOString() : current.publishedAt || "",
        publishedBy: isPublishing ? peerId : current.publishedBy || "",
        updatedAt: new Date().toISOString(),
        updatedBy: peerId
      };
      addAdminHubNotifications(state, state.boards[section].mentions, peerId, "board", section, `You were mentioned in ${state.boards[section].title}.`);
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/read-notifications") {
      const body = await readRequestJson(request);
      const scope = body.scope === "chat" ? "chat" : "board";
      const section = String(body.section || "");
      const state = await getAdminHubState();
      for (const notification of state.notifications || []) {
        if (notification.targetId === peerId && notification.scope === scope && (scope === "chat" || notification.section === section)) notification.read = true;
      }
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/read-board") {
      const body = await readRequestJson(request);
      const section = String(body.section || "");
      const state = await getAdminHubState();
      if (!state.boards[section]) throw new Error("Board not found.");
      state.reads ||= {};
      state.reads[peerId] ||= {};
      state.reads[peerId][section] = new Date().toISOString();
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/comment") {
      const body = await readRequestJson(request);
      const section = String(body.section || "");
      const state = await getAdminHubState();
      const board = state.boards[section];
      if (!board || (!board.published && !canEditAdminBoard(section, board, peerId))) throw new Error("That board is unavailable.");
      const text = String(body.text || "").trim().slice(0, 1200);
      if (!text) throw new Error("Write a comment first.");
      board.comments ||= [];
      board.comments.push({
        id: randomUUID(), authorId: peerId, text,
        quote: String(body.quote || "").trim().slice(0, 300),
        mentions: findAdminHubMentions(text), resolved: false,
        createdAt: new Date().toISOString()
      });
      addAdminHubNotifications(state, findAdminHubMentions(text), peerId, "board", section, `You were mentioned in a comment on ${board.title}.`);
      board.comments = board.comments.slice(-250);
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/comment-update") {
      const body = await readRequestJson(request);
      const state = await getAdminHubState();
      const board = state.boards[String(body.section || "")];
      const comment = board?.comments?.find((item) => item.id === body.commentId);
      if (!comment) throw new Error("Comment not found.");
      if (comment.authorId !== peerId && !canEditAdminBoard(board.section, board, peerId)) throw new Error("You cannot change that comment.");
      if (body.remove === true) board.comments = board.comments.filter((item) => item.id !== comment.id);
      else comment.resolved = body.resolved === true;
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/attachment") {
      const body = await readRequestJson(request);
      const section = String(body.section || "");
      const state = await getAdminHubState();
      const board = state.boards[section];
      if (!board || !canEditAdminBoard(section, board, peerId)) throw new Error("You cannot attach files to this board.");
      board.attachments ||= [];
      if (body.remove === true) {
        board.attachments = board.attachments.filter((item) => item.id !== body.attachmentId);
      } else {
        const dataUrl = String(body.dataUrl || "");
        if (!/^data:(?:image\/|video\/|application\/pdf)/i.test(dataUrl)) throw new Error("Choose an image, video, or PDF.");
        if (dataUrl.length > 1_250_000) throw new Error("Keep each attachment under about 900 KB.");
        if (board.attachments.length >= 6) throw new Error("This board already has 6 attachments.");
        board.attachments.push({ id: randomUUID(), name: String(body.name || "Attachment").slice(0, 120), type: String(body.type || ""), dataUrl, authorId: peerId, createdAt: new Date().toISOString() });
      }
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/feature") {
      const body = await readRequestJson(request);
      const section = String(body.section || "");
      const state = await getAdminHubState();
      const board = state.boards[section];
      if (!board || !canEditAdminBoard(section, board, peerId)) throw new Error("You cannot edit this board.");
      const feature = {
        id: randomUUID(),
        text: String(body.text || "").trim().slice(0, 300),
        completed: false,
        votes: {},
        status: "idea",
        assignedTo: "",
        dueDate: "",
        mentions: findAdminHubMentions(String(body.text || "")),
        createdAt: new Date().toISOString(),
        createdBy: peerId
      };
      if (!feature.text) throw new Error("Name the update idea first.");
      board.features.push(feature);
      addAdminHubNotifications(state, feature.mentions, peerId, "board", section, `You were mentioned in ${board.title}.`);
      board.updatedAt = new Date().toISOString();
      board.updatedBy = peerId;
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/feature-update") {
      const body = await readRequestJson(request);
      const section = String(body.section || "");
      const state = await getAdminHubState();
      const board = state.boards[section];
      const feature = board?.features.find((item) => item.id === body.featureId);
      if (!board || !feature || !canEditAdminBoard(section, board, peerId)) throw new Error("You cannot edit that update idea.");
      if (Object.prototype.hasOwnProperty.call(body, "completed")) feature.completed = body.completed === true;
      if (Object.prototype.hasOwnProperty.call(body, "text")) {
        feature.text = String(body.text || "").trim().slice(0, 300) || feature.text;
        feature.mentions = findAdminHubMentions(feature.text);
      }
      if (Object.prototype.hasOwnProperty.call(body, "status") && ["idea", "planned", "building", "testing", "released", "rejected"].includes(body.status)) feature.status = body.status;
      if (Object.prototype.hasOwnProperty.call(body, "assignedTo")) {
        const previousAssignee = feature.assignedTo;
        feature.assignedTo = ADMIN_HUB_IDS.has(String(body.assignedTo)) ? String(body.assignedTo) : "";
        if (feature.assignedTo && feature.assignedTo !== previousAssignee) addAdminHubNotifications(state, [feature.assignedTo], peerId, "board", section, `You were assigned an update in ${board.title}.`);
      }
      if (Object.prototype.hasOwnProperty.call(body, "dueDate")) feature.dueDate = /^\d{4}-\d{2}-\d{2}$/.test(String(body.dueDate)) ? String(body.dueDate) : "";
      if (body.remove === true) board.features = board.features.filter((item) => item.id !== feature.id);
      board.updatedAt = new Date().toISOString();
      board.updatedBy = peerId;
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    if (request.method === "POST" && url.pathname === "/admin-hub/api/vote") {
      const body = await readRequestJson(request);
      const state = await getAdminHubState();
      const board = state.boards[String(body.section || "")];
      const feature = board?.features.find((item) => item.id === body.featureId);
      if (!board?.published || !feature) throw new Error("That published idea is no longer available.");
      const vote = body.vote === "yes" ? "yes" : body.vote === "no" ? "no" : "";
      if (vote) feature.votes[peerId] = vote;
      else delete feature.votes[peerId];
      await setAdminHubState(state);
      sendJson(response, 200, { ok: true, state: visibleAdminHubState(state, peerId) }, corsHeaders);
      return;
    }

    sendJson(response, 404, { ok: false, message: "Unknown admin hub endpoint." }, corsHeaders);
  } catch (error) {
    sendJson(response, 400, { ok: false, message: error.message || "The admin hub request failed." }, corsHeaders);
  }
}

function defaultAdminHubState() {
  const now = new Date().toISOString();
  const boards = {};
  for (const [section, config] of Object.entries(ADMIN_HUB_SECTIONS)) {
    boards[section] = {
      section,
      title: section === "shared" ? "Shared roadmap" : `${config.label}'s update ideas`,
      contentHtml: "",
      ownerIds: config.ownerIds,
      collaborators: [],
      published: section === "shared",
      publishedAt: section === "shared" ? now : "",
      publishedBy: "",
      features: [],
      comments: [],
      attachments: [],
      updatedAt: now,
      updatedBy: ""
    };
  }
  return { version: 3, chat: [], boards, reads: {}, notifications: [], updates: [] };
}

async function getAdminHubState() {
  let stored = null;
  if (redis) stored = await redis.get("bypassium:admin-hub:state");
  else if (upstashRestEnabled) stored = await upstashCommand(["GET", "bypassium:admin-hub:state"]);
  else stored = memoryAdminHubState;
  if (!stored) return defaultAdminHubState();
  const parsed = typeof stored === "string" ? JSON.parse(stored) : stored;
  const fallback = defaultAdminHubState();
  const boards = {};
  for (const [section, baseBoard] of Object.entries(fallback.boards)) {
    const savedBoard = parsed.boards?.[section] || {};
    boards[section] = {
      ...baseBoard,
      ...savedBoard,
      features: Array.isArray(savedBoard.features) ? savedBoard.features : [],
      comments: Array.isArray(savedBoard.comments) ? savedBoard.comments : [],
      attachments: Array.isArray(savedBoard.attachments) ? savedBoard.attachments : []
    };
  }
  return { ...fallback, ...parsed, boards, reads: parsed.reads || {}, notifications: Array.isArray(parsed.notifications) ? parsed.notifications : [], chat: Array.isArray(parsed.chat) ? parsed.chat : [], updates: Array.isArray(parsed.updates) ? parsed.updates : [] };
}

async function setAdminHubState(state) {
  const payload = JSON.stringify(state);
  memoryAdminHubState = payload;
  if (redis) await redis.set("bypassium:admin-hub:state", payload);
  else if (upstashRestEnabled) await upstashCommand(["SET", "bypassium:admin-hub:state", payload]);
}

function visibleAdminHubState(state, peerId) {
  const boards = {};
  for (const [section, board] of Object.entries(state.boards || {})) {
    if (board.published || canEditAdminBoard(section, board, peerId)) {
      boards[section] = { ...board, canEdit: canEditAdminBoard(section, board, peerId) };
    } else {
      boards[section] = { section, title: board.title, published: false, private: true, canEdit: false, features: [] };
    }
  }
  const unreadSections = Object.entries(state.boards || {}).filter(([section, board]) => {
    if (!board.published || board.publishedBy === peerId || !board.publishedAt) return false;
    return new Date(state.reads?.[peerId]?.[section] || 0) < new Date(board.publishedAt);
  }).map(([section]) => section);
  const notifications = (state.notifications || []).filter((item) => item.targetId === peerId && !item.read).slice(-100);
  const typing = [...adminHubTyping.entries()].filter(([id, expiresAt]) => id !== peerId && Number(expiresAt) > Date.now()).map(([id]) => id);
  return { version: state.version || 3, chat: state.chat || [], boards, updates: state.updates || [], unreadSections, notifications, typing };
}

function addAdminHubNotifications(state, targetIds, authorId, scope, section, message) {
  state.notifications ||= [];
  for (const targetId of [...new Set(targetIds || [])]) {
    if (targetId === authorId) continue;
    if (state.notifications.some((item) => !item.read && item.targetId === targetId && item.scope === scope && item.section === section && item.message === message)) continue;
    state.notifications.push({ id: randomUUID(), targetId, authorId, scope, section, message, read: false, createdAt: new Date().toISOString() });
  }
  state.notifications = state.notifications.slice(-500);
}

function findAdminHubMentions(text) {
  const value = String(text || "").toLowerCase();
  const names = { owen: ["907623", "137096"], riley: ["396172"], coen: ["904674"], "bypassium admin": ["767838"], bypassium: ["767838"] };
  return [...new Set(Object.entries(names).filter(([name]) => value.includes(`@${name}`)).flatMap(([, ids]) => ids))];
}

function canEditAdminBoard(section, board, peerId) {
  return section === "shared"
    || (board.ownerIds || ADMIN_HUB_SECTIONS[section]?.ownerIds || []).includes(peerId)
    || (board.collaborators || []).includes(peerId);
}

function sanitizeAdminHubHtml(value = "") {
  return String(value || "")
    .replace(/<\/?(?:script|style|iframe|object|embed|form)[^>]*>/gi, "")
    .replace(/\son\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "")
    .replace(/javascript:/gi, "")
    .slice(0, 50000);
}

async function adminHubUserFromId(peerId) {
  const profile = await getProfile(peerId) || {};
  return adminHubUser(peerId, profile);
}

function adminHubUser(peerId, profile = {}) {
  return {
    peerId,
    displayName: profile.displayName || ADMIN_HUB_SECTIONS[Object.keys(ADMIN_HUB_SECTIONS).find((key) => ADMIN_HUB_SECTIONS[key].ownerIds.includes(peerId))]?.label || peerId,
    profilePicture: profile.profilePicture || "",
    badge: profile.badge || "Admin"
  };
}

function safeEqualString(first, second) {
  const firstBuffer = Buffer.from(String(first || ""));
  const secondBuffer = Buffer.from(String(second || ""));
  if (firstBuffer.length !== secondBuffer.length || !firstBuffer.length) return false;
  return timingSafeEqual(firstBuffer, secondBuffer);
}

async function adminGroupOrError(response, corsHeaders, groupIdValue) {
  const groupId = cleanAdminGroupId(groupIdValue);
  if (!groupId) {
    sendJson(response, 400, { ok: false, message: "Choose a valid group." }, corsHeaders);
    return null;
  }
  const group = await getGroup(groupId);
  if (!group) {
    sendJson(response, 404, { ok: false, message: "Group not found." }, corsHeaders);
    return null;
  }
  return group;
}

async function readRequestJson(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function sendJson(response, status, payload, corsHeaders = {}) {
  response.writeHead(status, {
    ...corsHeaders,
    "content-type": "application/json",
    "cache-control": "no-store"
  });
  response.end(JSON.stringify(payload));
}

function adminPageHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Bypassium Support</title>
  <style>
    :root { color-scheme: dark; --bg:#07111f; --panel:rgb(17 27 45 / .78); --panel2:rgb(25 39 64 / .86); --line:rgb(255 255 255 / .14); --text:#eef6ff; --muted:#9fb1c7; --accent:#62a8ff; --accent2:#22d3c5; --danger:#fb7185; --warn:#fbbf24; --ok:#34d399; font-family:Inter,ui-sans-serif,system-ui,Segoe UI,sans-serif; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; color:var(--text); background:radial-gradient(circle at 12% 0%, rgb(96 165 250 / .26), transparent 34%), radial-gradient(circle at 90% 18%, rgb(45 212 191 / .2), transparent 30%), var(--bg); }
    button,input,textarea { font:inherit; }
    button { border:0; border-radius:14px; padding:10px 13px; color:white; background:linear-gradient(180deg,color-mix(in srgb,var(--accent),white 12%),var(--accent)); cursor:pointer; font-weight:850; box-shadow:inset 0 1px 0 rgb(255 255 255 / .18),0 12px 28px rgb(0 0 0 / .22); }
    button:disabled { opacity:.48; cursor:not-allowed; box-shadow:none; }
    button.secondary { color:var(--text); background:rgb(255 255 255 / .07); border:1px solid var(--line); }
    button.danger { background:linear-gradient(180deg,color-mix(in srgb,var(--danger),white 10%),var(--danger)); }
    button.warn { background:linear-gradient(180deg,color-mix(in srgb,var(--warn),white 10%),#d97706); }
    input,textarea { width:100%; border:1px solid var(--line); border-radius:14px; padding:11px 12px; color:var(--text); background:rgb(4 12 24 / .52); outline:none; }
    textarea { min-height:76px; resize:vertical; }
    label { display:grid; gap:7px; color:var(--muted); font-size:12px; font-weight:800; text-transform:uppercase; }
    .shell { display:grid; grid-template-columns:minmax(280px,390px) minmax(0,1fr); gap:14px; min-height:100vh; padding:16px; }
    .card { border:1px solid var(--line); border-radius:24px; padding:16px; background:linear-gradient(145deg,var(--panel),rgb(10 20 36 / .74)); box-shadow:0 24px 70px rgb(0 0 0 / .28),inset 0 1px 0 rgb(255 255 255 / .12); backdrop-filter:blur(24px) saturate(1.25); }
    .stack { display:grid; gap:12px; }
    .brand { display:flex; align-items:center; gap:12px; }
    .logo { display:grid; place-items:center; width:52px; height:52px; border-radius:17px; background:linear-gradient(145deg,var(--accent),#1d4ed8); font-size:28px; font-weight:1000; box-shadow:inset 0 1px 0 rgb(255 255 255 / .22); }
    h1,h2,h3,p { margin:0; }
    h1 { font-size:31px; letter-spacing:0; }
    h2 { font-size:20px; }
    h3 { font-size:15px; }
    .muted { color:var(--muted); font-size:13px; line-height:1.45; }
    .token-row,.search-row,.actions,.split { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:8px; align-items:end; }
    .bulk-bar { display:grid; grid-template-columns:auto minmax(0,1fr) auto auto; gap:8px; align-items:center; padding:9px; border:1px solid var(--line); border-radius:15px; background:rgb(255 255 255 / .045); }
    .bulk-bar label,.row-check { display:flex; align-items:center; gap:8px; color:var(--muted); font-size:12px; font-weight:900; text-transform:none; }
    input[type="checkbox"] { width:auto; accent-color:var(--accent); }
    .status-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:9px; }
    .status { padding:11px; border:1px solid var(--line); border-radius:16px; background:rgb(255 255 255 / .06); }
    .status strong { display:block; font-size:20px; }
    .list { display:grid; gap:8px; max-height:55vh; overflow:auto; padding-right:3px; }
    .list-state { padding:11px; border:1px solid var(--line); border-radius:15px; background:rgb(255 255 255 / .045); }
    .row { display:grid; grid-template-columns:auto minmax(0,1fr) auto; align-items:center; gap:10px; padding:10px; border:1px solid var(--line); border-radius:17px; background:rgb(255 255 255 / .055); text-align:left; }
    .row:hover { border-color:color-mix(in srgb,var(--accent),white 18%); }
    .group-row { grid-template-columns:minmax(0,1fr) auto; }
    .account-open { min-width:0; display:grid; grid-template-columns:46px minmax(0,1fr); align-items:center; gap:10px; padding:0; border-radius:0; color:var(--text); background:transparent; box-shadow:none; text-align:left; }
    .avatar { width:46px; height:46px; border-radius:15px; overflow:hidden; display:grid; place-items:center; color:white; font-weight:1000; background:linear-gradient(145deg,var(--accent),var(--accent2)); }
    .avatar img { width:100%; height:100%; object-fit:cover; }
    .account-open strong,.account-open small { display:block; overflow:hidden; white-space:nowrap; text-overflow:ellipsis; }
    .account-open small { color:var(--muted); margin-top:3px; }
    .badge { display:inline-flex; align-items:center; min-height:25px; border-radius:999px; padding:3px 9px; font-size:12px; font-weight:900; color:var(--text); border:1px solid var(--line); background:rgb(255 255 255 / .07); }
    .profile-badge { display:inline-flex; align-items:center; width:max-content; max-width:100%; min-height:22px; margin-top:5px; padding:3px 9px; border:1px solid rgb(147 197 253 / .52); border-radius:999px; color:#dbeafe; background:linear-gradient(180deg,rgb(96 165 250 / .28),rgb(14 165 233 / .14)); box-shadow:inset 0 1px 0 rgb(255 255 255 / .22),0 10px 26px rgb(96 165 250 / .18); font-size:11px; font-weight:1000; letter-spacing:.01em; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .badge.bad { color:white; background:var(--danger); border-color:transparent; }
    .badge.ok { color:#042016; background:var(--ok); border-color:transparent; }
    .detail-head { display:flex; align-items:center; gap:14px; }
    .detail-head .avatar { width:72px; height:72px; border-radius:24px; font-size:28px; }
    .profile-edit { display:grid; grid-template-columns:86px minmax(0,1fr); gap:12px; align-items:start; }
    .profile-preview { width:86px; height:86px; border-radius:24px; font-size:32px; }
    .info-grid { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:9px; }
    .info { padding:10px; border:1px solid var(--line); border-radius:15px; background:rgb(255 255 255 / .052); }
    .info span { display:block; color:var(--muted); font-size:11px; font-weight:900; text-transform:uppercase; }
    .info strong { display:block; margin-top:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .danger-zone { border-color:color-mix(in srgb,var(--danger),white 8%); }
    .member-list { display:grid; gap:8px; max-height:390px; overflow:auto; padding-right:3px; }
    .member-row { display:grid; grid-template-columns:46px minmax(0,1fr); gap:10px; align-items:start; padding:10px; border:1px solid var(--line); border-radius:17px; background:rgb(255 255 255 / .052); }
    .member-meta strong,.member-meta small { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .member-actions { grid-column:1 / -1; display:flex; flex-wrap:wrap; gap:8px; }
    .member-actions button { padding:8px 10px; border-radius:12px; font-size:12px; }
    .role-chip { display:inline-flex; width:max-content; max-width:100%; margin-top:5px; padding:3px 9px; border-radius:999px; border:1px solid rgb(96 165 250 / .48); color:#dbeafe; background:rgb(96 165 250 / .16); font-size:11px; font-weight:1000; }
    .audit { max-height:240px; overflow:auto; display:grid; gap:7px; }
    .audit div { padding:9px; border:1px solid var(--line); border-radius:13px; background:rgb(255 255 255 / .045); }
    .hidden { display:none !important; }
    .toast { position:fixed; right:16px; bottom:16px; max-width:min(440px,calc(100vw - 32px)); padding:12px 14px; border:1px solid var(--line); border-radius:16px; background:var(--panel2); box-shadow:0 20px 60px rgb(0 0 0 / .32); }
    @media (max-width:860px) { .shell { grid-template-columns:1fr; } .info-grid,.status-grid { grid-template-columns:1fr; } }
  </style>
</head>
<body>
  <main class="shell">
    <section class="stack">
      <div class="card stack">
        <div class="brand"><div class="logo">B</div><div><p class="muted">Owner dashboard</p><h1>Bypassium Support</h1></div></div>
        <p class="muted">Protected server controls. No passwords or recovery phrases are shown here.</p>
        <div class="token-row">
          <label>Admin token<input id="token" type="password" autocomplete="off" placeholder="ADMIN_TOKEN"></label>
          <button id="saveToken">Unlock</button>
        </div>
        <p id="authStatus" class="muted">Checking server...</p>
      </div>
      <div class="card stack">
        <h2>Server</h2>
        <div id="statusGrid" class="status-grid"></div>
      </div>
      <div class="card stack">
        <div class="split"><div><h2>B-Coin pricing</h2><p class="muted">Changes apply immediately to connected users.</p></div><button id="savePricing">Save prices</button></div>
        <div class="info-grid" id="pricingGrid">
          <label>Attachment to 256 KB<input id="priceAttachment256" type="number" min="0" step="1"></label>
          <label>Attachment to 1 MB<input id="priceAttachment1" type="number" min="0" step="1"></label>
          <label>Attachment to 5 MB<input id="priceAttachment5" type="number" min="0" step="1"></label>
          <label>Attachment to 10 MB<input id="priceAttachment10" type="number" min="0" step="1"></label>
          <label>Attachment over 10 MB<input id="priceAttachmentOver10" type="number" min="0" step="1"></label>
          <label>Direct call / minute<input id="priceDirectCall" type="number" min="0" step="1"></label>
          <label>Group call / minute<input id="priceGroupCall" type="number" min="0" step="1"></label>
          <label>Free direct-call seconds / day<input id="priceFreeCallSeconds" type="number" min="0" step="1"></label>
          <label>Memory Deck Flip<input id="priceMemoryDeckFlip" type="number" min="0" step="1"></label>
          <label>Memory under 10s<input id="priceMemory10" type="number" min="0" step="1"></label>
          <label>Memory under 20s<input id="priceMemory20" type="number" min="0" step="1"></label>
          <label>Memory under 30s<input id="priceMemory30" type="number" min="0" step="1"></label>
          <label>Memory under 40s<input id="priceMemory40" type="number" min="0" step="1"></label>
          <label>Memory under 50s<input id="priceMemory50" type="number" min="0" step="1"></label>
          <label>Memory under 60s<input id="priceMemory60" type="number" min="0" step="1"></label>
          <label>Memory over 60s<input id="priceMemoryOver60" type="number" min="0" step="1"></label>
        </div>
        <p id="pricingStatus" class="muted">Unlock the dashboard to load pricing.</p>
      </div>
      <div class="card stack">
        <h2>Accounts</h2>
        <div class="search-row">
          <label>Search<input id="search" placeholder="Code or username"></label>
          <button id="searchBtn">Search</button>
        </div>
        <div class="bulk-bar">
          <label><input id="selectAll" type="checkbox"> Select shown</label>
          <span id="selectedCount" class="muted">0 selected</span>
          <button id="clearSelected" class="secondary" disabled>Clear</button>
          <button id="bulkDelete" class="danger" disabled>Delete selected</button>
        </div>
        <div id="accountList" class="list"></div>
      </div>
      <div class="card stack">
        <h2>Groups</h2>
        <div class="search-row">
          <label>Search<input id="groupSearch" placeholder="Group, owner, or member"></label>
          <button id="groupSearchBtn">Search</button>
        </div>
        <div id="groupList" class="list"></div>
      </div>
    </section>
    <section class="stack">
      <div id="detail" class="card stack">
        <h2>Select an account</h2>
        <p class="muted">Search by code or display name, then choose an account to manage.</p>
      </div>
      <div class="card stack">
        <div class="split"><h2>Audit log</h2><button id="refreshAudit" class="secondary">Refresh</button></div>
        <div id="audit" class="audit"></div>
      </div>
    </section>
  </main>
  <div id="toast" class="toast hidden"></div>
  <script>
    const state = { token: localStorage.getItem("bypassiumAdminToken") || "", selected: "", selectedGroup: "", selectedPeers: new Set(), searchTimer: 0, searchSeq: 0, groupSearchTimer: 0, groupSearchSeq: 0, profilePictureDraft: "", groupAvatarDraft: "", groupAvatarRemove: false };
    const $ = (id) => document.getElementById(id);
    $("token").value = state.token;
    $("saveToken").onclick = () => { state.token = $("token").value.trim(); localStorage.setItem("bypassiumAdminToken", state.token); refreshAll(); };
    $("searchBtn").onclick = () => searchAccounts();
    $("search").addEventListener("input", () => scheduleAccountSearch());
    $("search").addEventListener("keydown", (event) => { if (event.key === "Enter") searchAccounts(); });
    $("groupSearchBtn").onclick = () => searchGroups();
    $("groupSearch").addEventListener("input", () => scheduleGroupSearch());
    $("groupSearch").addEventListener("keydown", (event) => { if (event.key === "Enter") searchGroups(); });
    $("refreshAudit").onclick = () => loadAudit();
    $("selectAll").onchange = () => toggleShownSelection($("selectAll").checked);
    $("clearSelected").onclick = () => { state.selectedPeers.clear(); updateSelectionUi(); };
    $("bulkDelete").onclick = () => bulkDeleteSelected();
    $("savePricing").onclick = () => savePricing();

    const pricingFields = {
      attachmentUpTo256Kb: "priceAttachment256", attachmentUpTo1Mb: "priceAttachment1",
      attachmentUpTo5Mb: "priceAttachment5", attachmentUpTo10Mb: "priceAttachment10",
      attachmentOver10Mb: "priceAttachmentOver10", directCallPerMinute: "priceDirectCall",
      groupCallPerMinute: "priceGroupCall", directCallDailyFreeSeconds: "priceFreeCallSeconds",
      memoryDeckFlip: "priceMemoryDeckFlip",
      memoryUnder10Seconds: "priceMemory10", memoryUnder20Seconds: "priceMemory20",
      memoryUnder30Seconds: "priceMemory30", memoryUnder40Seconds: "priceMemory40",
      memoryUnder50Seconds: "priceMemory50", memoryUnder60Seconds: "priceMemory60",
      memoryOver60Seconds: "priceMemoryOver60"
    };

    async function loadPricing() {
      try {
        const payload = await api("/pricing");
        for (const [key, id] of Object.entries(pricingFields)) $(id).value = payload.pricing[key];
        $("pricingStatus").textContent = "Current server pricing loaded.";
      } catch (error) { $("pricingStatus").textContent = error.message; }
    }

    async function savePricing() {
      try {
        const values = {};
        for (const [key, id] of Object.entries(pricingFields)) values[key] = Math.max(0, Math.round(Number($(id).value) || 0));
        const payload = await api("/pricing", { method:"POST", body:JSON.stringify({ pricing:values }) });
        for (const [key, id] of Object.entries(pricingFields)) $(id).value = payload.pricing[key];
        $("pricingStatus").textContent = payload.message;
        toast(payload.message);
        await loadAudit();
      } catch (error) { $("pricingStatus").textContent = error.message; toast(error.message); }
    }

    async function api(path, options = {}) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);
      const response = await fetch("/admin/api" + path, {
        ...options,
        signal: controller.signal,
        headers: { "content-type": "application/json", authorization: "Bearer " + state.token, ...(options.headers || {}) }
      }).finally(() => clearTimeout(timeout));
      const payload = await parseJsonResponse(response);
      if (!response.ok || payload.ok === false) throw new Error(payload.message || "Request failed.");
      return payload;
    }
    async function parseJsonResponse(response) {
      const text = await response.text();
      if (!text.trim()) {
        return {
          ok: false,
          message: "Empty server response (" + response.status + "). Refresh the admin page; Render may have restarted or timed out."
        };
      }
      try {
        return JSON.parse(text);
      } catch {
        return {
          ok: false,
          message: "Bad server response (" + response.status + "): " + text.slice(0, 160)
        };
      }
    }
    async function refreshAll() { await Promise.allSettled([loadStatus(), loadPricing(), searchAccounts(), searchGroups(), loadAudit()]); }
    async function loadStatus() {
      try {
        const configResponse = await fetch("/admin/api/config");
        const config = await parseJsonResponse(configResponse);
        if (config.ok === false) throw new Error(config.message || "Could not load admin config.");
        if (!config.adminEnabled) $("authStatus").textContent = "ADMIN_TOKEN is not configured on the server.";
        else $("authStatus").textContent = state.token ? "Token saved locally in this browser." : "Enter ADMIN_TOKEN to unlock actions.";
        const status = await api("/status");
        $("statusGrid").innerHTML = ["storage","onlineClients","accounts","groups","queuedUsers","auditEntries"].map((key) => '<div class="status"><span class="muted">' + escapeHtml(key) + '</span><strong>' + escapeHtml(String(status[key])) + '</strong></div>').join("");
      } catch (error) {
        $("statusGrid").innerHTML = '<p class="muted">' + escapeHtml(error.message) + '</p>';
      }
    }
    async function searchAccounts() {
      const seq = ++state.searchSeq;
      $("accountList").innerHTML = '<p class="muted list-state">Searching...</p>';
      try {
        const q = encodeURIComponent($("search").value.trim());
        const payload = await api("/accounts?q=" + q);
        if (seq !== state.searchSeq) return;
        const accounts = Array.isArray(payload.accounts) ? payload.accounts : [];
        $("accountList").innerHTML = accounts.length ? accounts.map(accountRow).join("") : '<p class="muted list-state">No accounts found. Try their 6-digit code or a shorter name.</p>';
        wireAccountRows();
      } catch (error) {
        const message = error.name === "AbortError" ? "Search timed out. Try a 6-digit code or refresh after the server finishes waking up." : error.message;
        if (seq === state.searchSeq) $("accountList").innerHTML = '<p class="muted list-state">' + escapeHtml(message) + '</p>';
      }
    }
    function scheduleAccountSearch() {
      clearTimeout(state.searchTimer);
      state.searchTimer = setTimeout(() => searchAccounts(), 220);
    }
    function accountRow(account) {
      const avatar = account.profilePicture ? '<img src="' + escapeAttr(account.profilePicture) + '" alt="">' : escapeHtml((account.displayName || "B").slice(0,1).toUpperCase());
      const profileBadge = account.badge ? '<span class="profile-badge">' + escapeHtml(account.badge) + '</span>' : '';
      const flags = account.banned ? '<span class="badge bad">Banned</span>' : account.passwordResetRequired ? '<span class="badge">Reset required</span>' : '<span class="badge ok">Active</span>';
      return '<div class="row" data-row-peer="' + escapeAttr(account.peerId) + '"><label class="row-check" title="Select account"><input type="checkbox" data-select-peer="' + escapeAttr(account.peerId) + '"></label><button class="account-open" data-open-peer="' + escapeAttr(account.peerId) + '"><span class="avatar">' + avatar + '</span><span><strong>' + escapeHtml(account.displayName || "Bypassium User") + '</strong>' + profileBadge + '<small>' + escapeHtml(account.peerId + " - " + account.status) + '</small></span></button>' + flags + '</div>';
    }
    function wireAccountRows() {
      document.querySelectorAll("[data-open-peer]").forEach((button) => button.onclick = () => loadAccount(button.dataset.openPeer));
      document.querySelectorAll("[data-select-peer]").forEach((checkbox) => {
        checkbox.checked = state.selectedPeers.has(checkbox.dataset.selectPeer);
        checkbox.onchange = () => {
          if (checkbox.checked) state.selectedPeers.add(checkbox.dataset.selectPeer);
          else state.selectedPeers.delete(checkbox.dataset.selectPeer);
          updateSelectionUi();
        };
      });
      updateSelectionUi();
    }
    function updateSelectionUi() {
      const boxes = [...document.querySelectorAll("[data-select-peer]")];
      for (const box of boxes) box.checked = state.selectedPeers.has(box.dataset.selectPeer);
      const shownSelected = boxes.filter((box) => box.checked).length;
      $("selectedCount").textContent = state.selectedPeers.size + " selected";
      $("clearSelected").disabled = state.selectedPeers.size === 0;
      $("bulkDelete").disabled = state.selectedPeers.size === 0;
      $("selectAll").checked = boxes.length > 0 && shownSelected === boxes.length;
      $("selectAll").indeterminate = shownSelected > 0 && shownSelected < boxes.length;
    }
    function toggleShownSelection(checked) {
      document.querySelectorAll("[data-select-peer]").forEach((box) => {
        if (checked) state.selectedPeers.add(box.dataset.selectPeer);
        else state.selectedPeers.delete(box.dataset.selectPeer);
      });
      updateSelectionUi();
    }
    function clearDetail(message, title = "Select an account") {
      state.selected = "";
      state.selectedGroup = "";
      $("detail").innerHTML = '<h2>' + escapeHtml(title) + '</h2><p class="muted">' + escapeHtml(message || "Search by code or display name, then choose an account to manage.") + '</p>';
    }
    async function bulkDeleteSelected() {
      const peerIds = [...state.selectedPeers];
      if (!peerIds.length) return;
      const preview = peerIds.slice(0, 12).join(", ") + (peerIds.length > 12 ? "..." : "");
      if (!confirm("Delete " + peerIds.length + " account(s)?\\n" + preview + "\\n\\nThis removes accounts, sessions, queued messages, profiles, and group membership.")) return;
      try {
        const payload = await api("/bulk-delete-accounts", { method:"POST", body:JSON.stringify({ peerIds }) });
        state.selectedPeers.clear();
        if (payload.deleted && payload.deleted.includes(state.selected)) {
          clearDetail("Selected account was deleted. Search again if you need another account.");
        }
        const missingCount = (payload.missing || []).length;
        toast("Deleted " + (payload.deleted || []).length + " account(s)" + (missingCount ? "; " + missingCount + " were already gone." : "."));
        await refreshAll();
      } catch (error) { toast(error.message); }
    }
    async function deleteSingleAccount(peerId) {
      try {
        const payload = await api("/delete-account", { method:"POST", body:JSON.stringify({ peerId, confirm: $("deleteConfirm").value }) });
        state.selectedPeers.delete(peerId);
        clearDetail(payload.message || "Account deleted.");
        toast(payload.message || "Account deleted.");
        await refreshAll();
      } catch (error) { toast(error.message); }
    }
    async function searchGroups() {
      const seq = ++state.groupSearchSeq;
      $("groupList").innerHTML = '<p class="muted list-state">Searching...</p>';
      try {
        const q = encodeURIComponent($("groupSearch").value.trim());
        const payload = await api("/groups?q=" + q);
        if (seq !== state.groupSearchSeq) return;
        const groups = Array.isArray(payload.groups) ? payload.groups : [];
        $("groupList").innerHTML = groups.length ? groups.map(groupRow).join("") : '<p class="muted list-state">No groups found. Try a group name, owner name, or member code.</p>';
        wireGroupRows();
      } catch (error) {
        const message = error.name === "AbortError" ? "Group search timed out. Try again after the server wakes up." : error.message;
        if (seq === state.groupSearchSeq) $("groupList").innerHTML = '<p class="muted list-state">' + escapeHtml(message) + '</p>';
      }
    }
    function scheduleGroupSearch() {
      clearTimeout(state.groupSearchTimer);
      state.groupSearchTimer = setTimeout(() => searchGroups(), 220);
    }
    function groupRow(group) {
      const avatar = group.avatar ? '<img src="' + escapeAttr(group.avatar) + '" alt="">' : escapeHtml((group.name || "G").slice(0,1).toUpperCase());
      const lock = group.memberAddLocked ? '<span class="badge">Add locked</span>' : '<span class="badge ok">Open add</span>';
      return '<div class="row group-row"><button class="account-open" data-open-group="' + escapeAttr(group.groupId) + '"><span class="avatar">' + avatar + '</span><span><strong>' + escapeHtml(group.name || "Group chat") + '</strong><small>' + escapeHtml(group.memberCount + " members - owner " + (group.ownerName || group.ownerId || "unknown")) + '</small></span></button>' + lock + '</div>';
    }
    function wireGroupRows() {
      document.querySelectorAll("[data-open-group]").forEach((button) => button.onclick = () => loadGroup(button.dataset.openGroup));
    }
    async function loadGroup(groupId) {
      try {
        state.selected = "";
        state.selectedGroup = groupId;
        const payload = await api("/group?groupId=" + encodeURIComponent(groupId));
        renderGroupDetail(payload.group);
      } catch (error) { toast(error.message); }
    }
    function renderGroupDetail(group) {
      state.selected = "";
      state.selectedGroup = group.groupId;
      state.groupAvatarDraft = group.avatar || "";
      state.groupAvatarRemove = false;
      const avatar = group.avatar ? '<img src="' + escapeAttr(group.avatar) + '" alt="">' : escapeHtml((group.name || "G").slice(0,1).toUpperCase());
      $("detail").innerHTML = '<div class="detail-head"><span class="avatar">' + avatar + '</span><div><p class="muted">Group</p><h1>' + escapeHtml(group.name || "Group chat") + '</h1><p class="muted">' + escapeHtml(group.groupId) + '</p></div></div>'
        + '<div class="info-grid">'
        + info("Members", String(group.memberCount)) + info("Admins", String(group.adminCount)) + info("Owner", (group.ownerName || group.ownerId || "unknown"))
        + info("Adding", group.memberAddLocked ? "locked" : "members allowed") + info("Created", group.createdAt || "unknown") + info("Updated", group.updatedAt || "unknown")
        + '</div>'
        + '<div class="card stack"><h2>Group details</h2><div class="profile-edit"><span id="groupAvatarPreview" class="avatar profile-preview">' + groupAvatarHtml(group.avatar, group.name) + '</span><div class="stack"><label>Group name<input id="groupName" value="' + escapeAttr(group.name || "Group chat") + '" maxlength="80"></label><label>Group picture<input id="groupAvatarFile" type="file" accept="image/*"></label><label><input id="groupAddLocked" type="checkbox" ' + checked(group.memberAddLocked) + '> Only owner/admins can add members</label><div class="actions"><button id="saveGroupProfile">Save group</button><button id="removeGroupAvatar" class="secondary">Remove picture</button></div></div></div></div>'
        + '<div class="card stack"><h2>Add members</h2><p class="muted">Enter one or more 6-digit Bypassium codes. Existing members are skipped.</p><div class="search-row"><label>Codes<input id="groupAddMembers" placeholder="123456 234567"></label><button id="addGroupMembers">Add</button></div></div>'
        + '<div class="card stack"><h2>Members</h2><div class="member-list">' + (group.members || []).map((member) => groupMemberRow(member, group)).join("") + '</div></div>'
        + '<div class="card stack danger-zone"><h2>Delete group</h2><p class="muted">This removes the group record. Message contents are not shown here.</p><label>Type group ID or exact name<input id="deleteGroupConfirm" placeholder="' + escapeAttr(group.groupId) + '"></label><button class="danger" id="deleteGroup">Delete group</button></div>';
      $("groupAvatarFile").onchange = async () => {
        try {
          const file = $("groupAvatarFile").files && $("groupAvatarFile").files[0];
          if (!file) return;
          state.groupAvatarDraft = await compressProfileImage(file);
          state.groupAvatarRemove = false;
          $("groupAvatarPreview").innerHTML = groupAvatarHtml(state.groupAvatarDraft, $("groupName").value);
          toast("Group picture ready. Click Save group.");
        } catch (error) { toast(error.message); }
      };
      $("removeGroupAvatar").onclick = () => {
        state.groupAvatarDraft = "";
        state.groupAvatarRemove = true;
        $("groupAvatarPreview").innerHTML = groupAvatarHtml("", $("groupName").value);
        toast("Picture removed. Click Save group.");
      };
      $("saveGroupProfile").onclick = () => postGroupAction("/group-update", { groupId: group.groupId, name: $("groupName").value, avatar: state.groupAvatarDraft, removeAvatar: state.groupAvatarRemove, memberAddLocked: $("groupAddLocked").checked });
      $("addGroupMembers").onclick = () => postGroupAction("/group-add-members", { groupId: group.groupId, members: parseMemberCodes($("groupAddMembers").value) });
      $("deleteGroup").onclick = () => deleteGroupFromAdmin(group.groupId);
      document.querySelectorAll("[data-group-owner]").forEach((button) => button.onclick = () => postGroupAction("/group-transfer-owner", { groupId: group.groupId, memberId: button.dataset.groupOwner }));
      document.querySelectorAll("[data-group-admin]").forEach((button) => button.onclick = () => postGroupAction("/group-set-admin", { groupId: group.groupId, memberId: button.dataset.groupAdmin, isAdmin: button.dataset.adminValue === "true" }));
      document.querySelectorAll("[data-group-remove]").forEach((button) => button.onclick = () => postGroupAction("/group-remove-member", { groupId: group.groupId, memberId: button.dataset.groupRemove }));
    }
    function groupMemberRow(member, group) {
      const isOwner = member.peerId === group.ownerId;
      const isAdmin = (group.admins || []).includes(member.peerId);
      const avatar = member.profilePicture ? '<img src="' + escapeAttr(member.profilePicture) + '" alt="">' : escapeHtml((member.displayName || member.peerId || "U").slice(0,1).toUpperCase());
      const badge = member.badge ? '<span class="profile-badge">' + escapeHtml(member.badge) + '</span>' : '';
      const role = isOwner ? "Owner" : isAdmin ? "Admin" : "Member";
      const adminButton = isOwner ? '' : '<button class="secondary" data-group-admin="' + escapeAttr(member.peerId) + '" data-admin-value="' + (isAdmin ? "false" : "true") + '">' + (isAdmin ? "Remove admin" : "Make admin") + '</button>';
      const ownerButton = isOwner ? '' : '<button class="secondary" data-group-owner="' + escapeAttr(member.peerId) + '">Make owner</button>';
      const removeButton = '<button class="danger" data-group-remove="' + escapeAttr(member.peerId) + '">Remove</button>';
      return '<div class="member-row"><span class="avatar">' + avatar + '</span><span class="member-meta"><strong>' + escapeHtml(member.displayName || member.peerId) + '</strong>' + badge + '<small class="muted">' + escapeHtml(member.peerId + " - " + member.status) + (member.banned ? ' - banned' : '') + '</small><span class="role-chip">' + escapeHtml(role) + '</span></span><div class="member-actions">' + ownerButton + adminButton + removeButton + '</div></div>';
    }
    async function postGroupAction(path, body) {
      try {
        const payload = await api(path, { method:"POST", body:JSON.stringify(body) });
        toast(payload.message || "Done.");
        if (payload.group) renderGroupDetail(payload.group);
        else if (payload.deleted) clearDetail(payload.message || "Group deleted.", "Select a group");
        await Promise.allSettled([loadStatus(), searchGroups(), loadAudit()]);
        return payload;
      } catch (error) { toast(error.message); throw error; }
    }
    async function deleteGroupFromAdmin(groupId) {
      try {
        const payload = await api("/delete-group", { method:"POST", body:JSON.stringify({ groupId, confirm: $("deleteGroupConfirm").value }) });
        clearDetail(payload.message || "Group deleted.", "Select a group");
        toast(payload.message || "Group deleted.");
        await refreshAll();
      } catch (error) { toast(error.message); }
    }
    function parseMemberCodes(value) {
      return [...new Set(String(value || "").match(/\d{6}/g) || [])];
    }
    function groupAvatarHtml(avatar, name) {
      return avatar ? '<img src="' + escapeAttr(avatar) + '" alt="">' : escapeHtml((name || "G").slice(0,1).toUpperCase());
    }
    async function loadAccount(peerId) {
      try {
        state.selectedGroup = "";
        state.selected = peerId;
        const payload = await api("/account?peerId=" + encodeURIComponent(peerId));
        renderDetail(payload.account);
      } catch (error) { toast(error.message); }
    }
    function renderDetail(account) {
      const avatar = account.profilePicture ? '<img src="' + escapeAttr(account.profilePicture) + '" alt="">' : escapeHtml((account.displayName || "B").slice(0,1).toUpperCase());
      const profileBadge = account.badge ? '<span class="profile-badge">' + escapeHtml(account.badge) + '</span>' : '';
      state.profilePictureDraft = account.profilePicture || "";
      $("detail").innerHTML = '<div class="detail-head"><span class="avatar">' + avatar + '</span><div><p class="muted">' + escapeHtml(account.peerId) + '</p><h1>' + escapeHtml(account.displayName || "Bypassium User") + '</h1>' + profileBadge + '<p class="muted">' + escapeHtml(account.status) + '</p></div></div>'
         + '<div class="info-grid">'
         + info("Password", account.hasPassword ? "set" : "not set") + info("Recovery", account.hasRecoveryPhrase ? "exists" : "missing") + info("Queued", String(account.queuedMessages))
         + info("Sessions", String(account.sessionCount)) + info("Groups", String(account.groupCount)) + info("Created", account.createdAt || "unknown")
         + '</div>'
        + '<div class="card stack"><h2>Wallet</h2><div class="info-grid">' + info("Balance", Number(account.wallet?.balance || 0).toLocaleString() + " B") + info("Status", account.wallet?.frozen ? "Frozen" : "Active") + '</div><label>Adjustment (whole B-Coins; use a negative number to remove)<input id="walletDelta" type="number" step="1" placeholder="500"></label><label>Mandatory reason<input id="walletReason" maxlength="240" placeholder="Why is this adjustment needed?"></label><div class="actions"><button id="adjustWallet">Apply adjustment</button><button id="freezeWallet" class="warn">' + (account.wallet?.frozen ? "Unfreeze wallet" : "Freeze wallet") + '</button></div><div class="stack">' + (account.wallet?.history || []).map(walletTransactionHtml).join("") + '</div></div>'
        + '<div class="card stack"><h2>Profile moderation</h2><div class="profile-edit"><span id="profilePreview" class="avatar profile-preview">' + profilePreviewHtml(account.profilePicture, account.displayName) + '</span><div class="stack"><label>Username<input id="profileDisplayName" value="' + escapeAttr(account.displayName || "Bypassium User") + '" maxlength="80"></label><label>Public badge<input id="profileBadge" value="' + escapeAttr(account.badge || "") + '" maxlength="32" placeholder="Updates Director"></label><label>Profile picture<input id="profilePictureFile" type="file" accept="image/*"></label><div class="actions"><button id="saveProfile">Save profile</button><button id="removeProfilePicture" class="secondary">Remove picture</button></div><p class="muted">Badges appear as separate premium labels next to the username. Leave blank for no badge.</p></div></div></div>'
        + '<div class="card stack danger-zone"><h2>Ban</h2><label>Reason<textarea id="banReason" placeholder="Reason shown internally"></textarea></label><label>Ban until optional<input id="banUntil" type="datetime-local"></label><div class="actions"><button class="danger" id="banBtn">Ban account</button><button class="secondary" id="unbanBtn">Unban</button></div><p class="muted">' + escapeHtml(account.banned ? "Currently banned: " + (account.banReason || "no reason") : "Not banned.") + '</p></div>'
        + '<div class="card stack"><h2>Restrictions</h2><label><input id="sendDisabled" type="checkbox" ' + checked(account.sendDisabled) + '> Stop sending messages</label><label><input id="groupsDisabled" type="checkbox" ' + checked(account.groupsDisabled) + '> Stop creating/joining groups</label><label><input id="quickAddHidden" type="checkbox" ' + checked(account.quickAddHidden) + '> Hide from Quick Add/search</label><button id="saveRestrictions">Save restrictions</button></div>'
        + '<div class="card stack"><h2>Recovery</h2><p class="muted">Force reset creates a one-time owner reset code. It does not reveal the old password.</p><button class="warn" id="forceReset">Force password reset</button><p id="resetOutput" class="muted"></p></div>'
        + '<div class="card stack"><h2>Sessions and queue</h2><div class="actions"><button id="revokeSessions">Revoke sessions</button><button class="secondary" id="clearQueue">Clear offline queue</button></div></div>'
        + '<div class="card stack danger-zone"><h2>Delete</h2><label>Type code to confirm<input id="deleteConfirm" placeholder="' + escapeAttr(account.peerId) + '"></label><button class="danger" id="deleteAccount">Delete account</button></div>';
      $("profilePictureFile").onchange = async () => {
        try {
          const file = $("profilePictureFile").files && $("profilePictureFile").files[0];
          if (!file) return;
          state.profilePictureDraft = await compressProfileImage(file);
          $("profilePreview").innerHTML = profilePreviewHtml(state.profilePictureDraft, $("profileDisplayName").value);
          toast("Picture ready. Click Save profile.");
        } catch (error) { toast(error.message); }
      };
      $("removeProfilePicture").onclick = () => {
        state.profilePictureDraft = "";
        $("profilePreview").innerHTML = profilePreviewHtml("", $("profileDisplayName").value);
        toast("Picture removed. Click Save profile.");
      };
      $("saveProfile").onclick = () => postAction("/profile", { peerId: account.peerId, displayName: $("profileDisplayName").value, badge: $("profileBadge").value, profilePicture: state.profilePictureDraft, removeProfilePicture: !state.profilePictureDraft });
      $("adjustWallet").onclick = () => postAction("/wallet-adjust", { peerId: account.peerId, delta: Number($("walletDelta").value), reason: $("walletReason").value });
      $("freezeWallet").onclick = () => postAction("/wallet-freeze", { peerId: account.peerId, frozen: !account.wallet?.frozen, reason: $("walletReason").value || (account.wallet?.frozen ? "Wallet restored" : "Frozen by Bypassium Support") });
      document.querySelectorAll("[data-wallet-reverse]").forEach((button) => button.onclick = () => postAction("/wallet-reverse", { transactionId: button.dataset.walletReverse, reason: $("walletReason").value || "Admin reversal" }));
      $("banBtn").onclick = () => postAction("/ban", { peerId: account.peerId, reason: $("banReason").value, bannedUntil: $("banUntil").value });
      $("unbanBtn").onclick = () => postAction("/unban", { peerId: account.peerId });
      $("saveRestrictions").onclick = () => postAction("/restrictions", { peerId: account.peerId, sendDisabled: $("sendDisabled").checked, groupsDisabled: $("groupsDisabled").checked, quickAddHidden: $("quickAddHidden").checked });
      $("forceReset").onclick = async () => { const payload = await postAction("/force-reset", { peerId: account.peerId }, false); $("resetOutput").textContent = "Reset code: " + payload.resetCode + " - expires " + new Date(payload.expiresAt).toLocaleString(); };
      $("revokeSessions").onclick = () => postAction("/revoke-sessions", { peerId: account.peerId });
      $("clearQueue").onclick = () => postAction("/clear-queue", { peerId: account.peerId });
      $("deleteAccount").onclick = () => deleteSingleAccount(account.peerId);
    }
    function profilePreviewHtml(profilePicture, displayName) {
      return profilePicture ? '<img src="' + escapeAttr(profilePicture) + '" alt="">' : escapeHtml((displayName || "B").slice(0,1).toUpperCase());
    }
    function info(label, value) { return '<div class="info"><span>' + escapeHtml(label) + '</span><strong>' + escapeHtml(value) + '</strong></div>'; }
    function walletTransactionHtml(transaction) {
      const reversible = ["payment", "admin_adjustment"].includes(transaction.type) && transaction.status === "completed";
      return '<div class="member-row"><span class="member-meta"><strong>' + escapeHtml(transaction.type.replaceAll("_", " ") + " · " + Number(transaction.amount || 0).toLocaleString() + " B") + '</strong><small class="muted">' + escapeHtml((transaction.caption || transaction.reason || "") + " · " + new Date(transaction.createdAt).toLocaleString()) + '</small></span>' + (reversible ? '<button class="secondary" data-wallet-reverse="' + escapeAttr(transaction.transactionId) + '">Reverse</button>' : '') + '</div>';
    }
    function checked(value) { return value ? "checked" : ""; }
    async function postAction(path, body, reload = true) {
      try {
        const payload = await api(path, { method:"POST", body:JSON.stringify(body) });
        toast("Done.");
        if (payload.account) renderDetail(payload.account);
        else if (payload.wallet && state.selected) await loadAccount(state.selected);
        if (reload) await refreshAll();
        return payload;
      } catch (error) { toast(error.message); throw error; }
    }
    async function loadAudit() {
      try {
        const payload = await api("/audit");
        $("audit").innerHTML = payload.audit.length ? payload.audit.map((entry) => '<div><strong>' + escapeHtml(entry.action) + '</strong> <span class="muted">' + escapeHtml(entry.peerId || "") + '</span><br><span class="muted">' + escapeHtml(new Date(entry.at).toLocaleString()) + '</span></div>').join("") : '<p class="muted">No audit entries.</p>';
      } catch (error) { $("audit").innerHTML = '<p class="muted">' + escapeHtml(error.message) + '</p>'; }
    }
    function toast(message) { $("toast").textContent = message; $("toast").classList.remove("hidden"); setTimeout(() => $("toast").classList.add("hidden"), 1800); }
    function compressProfileImage(file) {
      return new Promise((resolve, reject) => {
        if (!file.type.startsWith("image/")) { reject(new Error("Choose an image file.")); return; }
        const reader = new FileReader();
        reader.onerror = () => reject(new Error("Could not read that image."));
        reader.onload = () => {
          const image = new Image();
          image.onerror = () => reject(new Error("Could not decode that image."));
          image.onload = () => {
            const maxSide = 160;
            const scale = Math.min(1, maxSide / Math.max(image.width, image.height));
            const canvas = document.createElement("canvas");
            canvas.width = Math.max(1, Math.round(image.width * scale));
            canvas.height = Math.max(1, Math.round(image.height * scale));
            const context = canvas.getContext("2d");
            context.drawImage(image, 0, 0, canvas.width, canvas.height);
            let dataUrl = canvas.toDataURL("image/jpeg", .78);
            if (dataUrl.length > 18000) dataUrl = canvas.toDataURL("image/jpeg", .58);
            if (dataUrl.length > 18000) reject(new Error("That picture is still too large. Try a smaller crop."));
            else resolve(dataUrl);
          };
          image.src = reader.result;
        };
        reader.readAsDataURL(file);
      });
    }
    function escapeHtml(value) { return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[char])); }
    function escapeAttr(value) { return escapeHtml(value).replace(new RegExp(String.fromCharCode(96), "g"), "&#96;"); }
    refreshAll();
  </script>
</body>
</html>`;
}

// Registers a permanent Bypassium ID and persists its public key for encrypted relay messages.
async function registerClient(socket, message) {
  const byPassiumId = String(message.peerId || "").trim();
  if (!/^\d{6}$/.test(byPassiumId) || !message.publicKeyJwk) {
    send(socket, { type: "error", message: "Registration requires a 6-digit ID and public key." });
    return;
  }
  const account = await getAccount(byPassiumId);
  const accountBlock = await accountBlockInfo(byPassiumId, "account");
  if (accountBlock) {
    send(socket, {
      type: accountBlock.code === "account-banned" ? "account-banned" : "account-auth-required",
      peerId: byPassiumId,
      ...accountBlock
    });
    return;
  }
  const storedPublicKey = await getPublicKey(byPassiumId);
  const storedKeyMatches = !storedPublicKey || samePublicKey(storedPublicKey, message.publicKeyJwk);
  if (account?.passwordHash && !(await validSession(byPassiumId, message.sessionToken))) {
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
      encryptedHistorySync: true,
      persistentEncryptedHistory: historyTtlSeconds() === 0,
      historyBackfill: true,
      quickAddDirectory: true,
      audioCalls: true,
      groupCalls: true,
      maxGroupCallMembers: MAX_GROUP_CALL_MEMBERS,
      encryptedStories: true,
      encryptedStoryFeedback: true,
      encryptedReels: true,
      encryptedSocialDrafts: true,
      storyWatchAnalytics: true,
      accounts: true,
      contactSync: true,
      authoritativeWallets: true,
      attachmentDeliveryBilling: true,
      callTimeBilling: true,
      callDailyFreeSeconds: pricing.directCallDailyFreeSeconds,
      callBlockSeconds: CALL_BLOCK_SECONDS,
      callBlockCost: pricing.directCallPerMinute,
      groupCallBlockCost: pricing.groupCallPerMinute,
      pricing: publicPricing(),
      walletLedger: true,
      serverArcadeRewards: true
    },
    account: publicAccountStatus(account, Boolean(account?.passwordHash)),
    contacts: await getSyncedContacts(byPassiumId),
    wallet: await walletSummary(byPassiumId)
  });
  await deliverOfflineMessages(socket);
}

async function syncClient(socket) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  send(socket, {
    type: "sync-complete",
    groups: await getGroupsForMember(peerId),
    contacts: await getSyncedContacts(peerId),
    syncedAt: new Date().toISOString()
  });
  await sendContactStatuses(socket, [...(socket.watchedContacts || [])]);
  await deliverOfflineMessages(socket);
}

async function syncHistoryMessages(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const requested = Number(message.limit);
  const limit = Math.min(
    maxHistorySyncLimit(),
    Math.max(50, Number.isFinite(requested) && requested > 0 ? requested : defaultHistorySyncLimit())
  );
  await deliverHistoryMessages(socket, limit);
}

async function backfillHistoryMessages(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!(await enforceAccountAction(socket, peerId, "send"))) return;
  if (!allowUserAction(socket, "message")) return;
  const entries = Array.isArray(message.entries) ? message.entries.slice(0, 80) : [];
  let stored = 0;
  for (const entry of entries) {
    if (!validEncryptedPayload(entry?.encrypted)) continue;
    const messageId = String(entry.messageId || "").trim();
    if (!messageId) continue;
    const sentAt = entry.sentAt || new Date().toISOString();
    const historyDirection = entry.historyDirection === "outbound" ? "outbound" : "inbound";
    const historyKind = entry.historyKind === "group" ? "group" : "direct";
    if (historyKind === "group") {
      const groupId = String(entry.groupId || "").trim();
      if (!groupId) continue;
      const existingGroup = await getGroup(groupId);
      if (existingGroup && !existingGroup.members.includes(peerId)) continue;
      const senderId = String(entry.senderId || entry.from || peerId).trim();
      if (!/^\d{6}$/.test(senderId)) continue;
      const members = normalizeMembers(entry.members || existingGroup?.members || [peerId, senderId]);
      if (!members.includes(peerId)) members.push(peerId);
      await queueHistoryMessage(peerId, {
        type: "group-message",
        historyKind: "group",
        historyDirection,
        historyPeerId: senderId,
        groupId,
        groupName: String(entry.groupName || existingGroup?.name || "Group chat").slice(0, 80),
        members,
        messageId,
        from: senderId,
        profile: sanitizeProfile(entry.profile || {}),
        publicKeyJwk: socket.publicKeyJwk,
        senderPublicKeyJwk: entry.senderPublicKeyJwk || null,
        encrypted: entry.encrypted,
        sentAt,
        selfEncrypted: true
      });
      stored += 1;
      continue;
    }

    const historyPeerId = String(entry.historyPeerId || "").trim();
    const from = String(entry.from || (historyDirection === "outbound" ? peerId : historyPeerId)).trim();
    if (!/^\d{6}$/.test(historyPeerId) || !/^\d{6}$/.test(from)) continue;
    await queueHistoryMessage(peerId, {
      type: "direct-message",
      historyKind: "direct",
      historyDirection,
      historyPeerId,
      messageId,
      from,
      profile: sanitizeProfile(entry.profile || {}),
      peerProfile: sanitizeProfile(entry.peerProfile || {}),
      publicKeyJwk: socket.publicKeyJwk,
      peerPublicKeyJwk: entry.peerPublicKeyJwk || null,
      encrypted: entry.encrypted,
      sentAt,
      selfEncrypted: true
    });
    stored += 1;
  }
  send(socket, {
    type: "history-backfill-result",
    requestId: String(message.requestId || ""),
    ok: true,
    stored,
    received: entries.length
  });
}

// Stores one encrypted story payload plus a separately wrapped content key for
// each approved contact. The server can route the story but cannot decrypt it.
async function publishStory(socket, message = {}) {
  const ownerId = getRegisteredSender(socket);
  if (!ownerId || !(await enforceAccountAction(socket, ownerId, "send"))) return;
  if (!allowUserAction(socket, "story")) return;
  const storyId = String(message.storyId || "").trim();
  const encryptedContent = message.encryptedContent;
  if (!/^[a-zA-Z0-9-]{12,80}$/.test(storyId) || !validEncryptedPayload(encryptedContent)) {
    send(socket, { type: "story-publish-result", requestId: String(message.requestId || ""), ok: false, message: "That story could not be prepared." });
    return;
  }
  const commandSize = JSON.stringify(message).length;
  if (commandSize > MAX_WEBSOCKET_PAYLOAD_CHARS - 200_000) {
    send(socket, { type: "story-publish-result", requestId: String(message.requestId || ""), ok: false, message: "That story is too large to upload." });
    return;
  }
  const allowedContacts = new Set((await getSyncedContacts(ownerId))
    .filter((contact) => contact.accepted !== false && !contact.blocked)
    .map((contact) => contact.id));
  allowedContacts.add(ownerId);
  const encryptedKeys = {};
  for (const entry of (Array.isArray(message.keys) ? message.keys : []).slice(0, MAX_STORY_RECIPIENTS + 1)) {
    const peerId = cleanPeerId(entry?.to);
    if (!peerId || !allowedContacts.has(peerId) || !validEncryptedPayload(entry?.encryptedKey)) continue;
    encryptedKeys[peerId] = entry.encryptedKey;
  }
  if (!encryptedKeys[ownerId]) {
    send(socket, { type: "story-publish-result", requestId: String(message.requestId || ""), ok: false, message: "The story could not be encrypted for this account." });
    return;
  }
  const createdAtMs = Date.now();
  const contentKind = ["reel", "highlight"].includes(message.contentKind) ? message.contentKind : "story";
  const expiresAtMs = createdAtMs + contentRecordTtlSeconds({ contentKind }) * 1000;
  const record = {
    storyId,
    ownerId,
    contentKind,
    createdAt: new Date(createdAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    profile: sanitizeProfile(message.profile || localProfile(ownerId)),
    encryptedContent,
    encryptedKeys
  };
  await setStoryRecord(record);
  for (const viewerId of Object.keys(encryptedKeys)) {
    const envelope = await storyEnvelopeForViewer(record, viewerId);
    if (envelope) sendToClient(viewerId, { type: "story-updated", story: envelope });
  }
  send(socket, {
    type: "story-publish-result",
    requestId: String(message.requestId || ""),
    ok: true,
    storyId,
    expiresAt: record.expiresAt,
    recipientCount: Math.max(0, Object.keys(encryptedKeys).length - 1)
  });
}

async function syncStories(socket) {
  const viewerId = getRegisteredSender(socket);
  if (!viewerId) return;
  const stories = await getStoriesForViewer(viewerId);
  let sent = 0;
  for (let index = 0; index < stories.length; index += 8) {
    const envelopes = (await Promise.all(stories.slice(index, index + 8).map((story) => storyEnvelopeForViewer(story, viewerId)))).filter(Boolean);
    let batch = [];
    let batchCharacters = 64;
    for (const envelope of envelopes) {
      const envelopeCharacters = JSON.stringify(envelope).length + 1;
      if (batch.length && batchCharacters + envelopeCharacters > MAX_WEBSOCKET_PAYLOAD_CHARS - 250_000) {
        send(socket, { type: "story-items", stories: batch });
        sent += batch.length;
        batch = [];
        batchCharacters = 64;
      }
      batch.push(envelope);
      batchCharacters += envelopeCharacters;
    }
    if (batch.length) {
      send(socket, { type: "story-items", stories: batch });
      sent += batch.length;
    }
    await yieldToSocketTraffic();
  }
  send(socket, { type: "story-sync-complete", count: sent });
}

async function viewStory(socket, message = {}) {
  const viewerId = getRegisteredSender(socket);
  const storyId = String(message.storyId || "").trim();
  if (!viewerId || !storyId) return;
  const story = await getStoryRecord(storyId);
  if (!story || !story.encryptedKeys?.[viewerId] || story.ownerId === viewerId) return;
  const viewerProfile = sanitizeProfile(await getProfile(viewerId) || localProfile(viewerId));
  const view = await addStoryView(storyId, viewerId, viewerProfile, story);
  sendToClient(story.ownerId, {
    type: "story-viewed",
    storyId,
    viewerId,
    viewedAt: view.viewedAt,
    profile: viewerProfile
  });
}

// Updates the viewer's aggregate watch record without storing watched content.
async function recordStoryWatch(socket, message = {}) {
  const viewerId = getRegisteredSender(socket);
  const storyId = String(message.storyId || "").trim();
  const story = viewerId && storyId ? await getStoryRecord(storyId) : null;
  if (!story || !story.encryptedKeys?.[viewerId] || story.ownerId === viewerId) return;
  const watchedMs = Math.max(0, Math.min(24 * 60 * 60 * 1000, Math.round(Number(message.watchedMs) || 0)));
  const durationMs = Math.max(1, Math.min(24 * 60 * 60 * 1000, Math.round(Number(message.durationMs) || 1)));
  const existing = (await getStoryViews(storyId)).find((record) => record.viewerId === viewerId) || {};
  const record = {
    ...existing,
    viewerId,
    viewedAt: existing.viewedAt || new Date().toISOString(),
    profile: existing.profile || sanitizeProfile(await getProfile(viewerId) || localProfile(viewerId)),
    watchedMs: Math.max(Number(existing.watchedMs) || 0, watchedMs),
    durationMs: Math.max(Number(existing.durationMs) || 0, durationMs),
    completed: Boolean(existing.completed || message.completed || watchedMs >= durationMs * 0.9),
    lastWatchedAt: new Date().toISOString()
  };
  await addStoryView(storyId, viewerId, record.profile, story, record);
  sendToClient(story.ownerId, { type: "story-viewed", storyId, ...record });
}

async function saveSocialDraft(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const kind = message.kind === "reel" ? "reel" : message.kind === "story" ? "story" : "";
  const encrypted = message.encrypted;
  const requestId = String(message.requestId || "");
  if (!peerId || !kind || !validEncryptedPayload(encrypted) || JSON.stringify(message).length > MAX_WEBSOCKET_PAYLOAD_CHARS - 200_000) {
    send(socket, { type: "draft-save-result", requestId, ok: false, message: "That encrypted draft is too large to sync." });
    return;
  }
  const record = { kind, encrypted, updatedAt: new Date().toISOString() };
  if (!memorySocialDrafts.has(peerId)) memorySocialDrafts.set(peerId, new Map());
  memorySocialDrafts.get(peerId).set(kind, record);
  if (redis) await redis.set(socialDraftKey(peerId, kind), JSON.stringify(record), "EX", SOCIAL_DRAFT_TTL_SECONDS);
  if (upstashRestEnabled) await upstashCommand(["SET", socialDraftKey(peerId, kind), JSON.stringify(record), "EX", SOCIAL_DRAFT_TTL_SECONDS]);
  send(socket, { type: "draft-save-result", requestId, ok: true, kind, updatedAt: record.updatedAt });
}

async function syncSocialDrafts(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const requestId = String(message.requestId || "");
  if (!peerId) return;
  const drafts = [];
  for (const kind of ["story", "reel"]) {
    let record = memorySocialDrafts.get(peerId)?.get(kind) || null;
    let stored = null;
    if (!record && redis) stored = await redis.get(socialDraftKey(peerId, kind));
    if (!record && upstashRestEnabled) stored = await upstashCommand(["GET", socialDraftKey(peerId, kind)]);
    if (!record && stored) record = safeJsonParse(stored);
    if (record?.encrypted) {
      if (!memorySocialDrafts.has(peerId)) memorySocialDrafts.set(peerId, new Map());
      memorySocialDrafts.get(peerId).set(kind, record);
      drafts.push(record);
    }
  }
  send(socket, { type: "draft-sync-result", requestId, ok: true, drafts });
}

async function deleteSocialDraft(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const kind = message.kind === "reel" ? "reel" : message.kind === "story" ? "story" : "";
  const requestId = String(message.requestId || "");
  if (!peerId || !kind) return;
  memorySocialDrafts.get(peerId)?.delete(kind);
  if (redis) await redis.del(socialDraftKey(peerId, kind));
  if (upstashRestEnabled) await upstashCommand(["DEL", socialDraftKey(peerId, kind)]);
  send(socket, { type: "draft-delete-result", requestId, ok: true, kind });
}

// Stores owner-readable encrypted comments and one replaceable reaction per
// viewer. Comment text never needs to be visible to the relay server.
async function submitStoryFeedback(socket, message = {}) {
  const viewerId = getRegisteredSender(socket);
  if (!viewerId || !(await enforceAccountAction(socket, viewerId, "send")) || !allowUserAction(socket, "story")) return;
  const storyId = String(message.storyId || "").trim();
  const story = storyId ? await getStoryRecord(storyId) : null;
  if (!story || !story.encryptedKeys?.[viewerId]) {
    send(socket, { type: "story-feedback-result", requestId: String(message.requestId || ""), ok: false, message: "That story is no longer available." });
    return;
  }
  const kind = message.kind === "comment" ? "comment" : message.kind === "reaction" ? "reaction" : "";
  const feedbackId = String(message.feedbackId || "").trim();
  const encrypted = message.encrypted;
  if (!kind || !/^[a-zA-Z0-9-]{12,80}$/.test(feedbackId) || !validEncryptedPayload(encrypted) || JSON.stringify(message).length > 100_000) {
    send(socket, { type: "story-feedback-result", requestId: String(message.requestId || ""), ok: false, message: "That response could not be sent." });
    return;
  }
  const reaction = kind === "reaction" && ["like", "dislike", "none"].includes(message.reaction) ? message.reaction : "";
  if (kind === "reaction" && !reaction) {
    send(socket, { type: "story-feedback-result", requestId: String(message.requestId || ""), ok: false, message: "Choose Like or Dislike." });
    return;
  }
  if (kind === "reaction" && story.ownerId === viewerId) {
    send(socket, { type: "story-feedback-result", requestId: String(message.requestId || ""), ok: false, message: "You cannot react to your own story." });
    return;
  }
  const record = {
    feedbackId,
    storyId,
    ownerId: story.ownerId,
    viewerId,
    kind,
    encryptionMode: kind === "comment" && message.encryptionMode === "story" ? "story" : "pair",
    reaction,
    encrypted,
    createdAt: new Date().toISOString(),
    profile: sanitizeProfile(await getProfile(viewerId) || localProfile(viewerId)),
    viewerPublicKeyJwk: socket.publicKeyJwk
  };
  if (kind === "reaction") await setStoryReaction(record, story);
  else await appendStoryComment(record, story);
  const envelope = await storyFeedbackEnvelope(record, story);
  if (record.encryptionMode === "story") {
    for (const recipientId of Object.keys(story.encryptedKeys || {})) {
      sendToClient(recipientId, { type: "story-feedback", feedback: envelope });
    }
  } else {
    sendToClient(story.ownerId, { type: "story-feedback", feedback: envelope });
  }
  send(socket, {
    type: "story-feedback-result",
    requestId: String(message.requestId || ""),
    ok: true,
    feedback: envelope
  });
}

async function recordStoryShare(socket, message = {}) {
  const viewerId = getRegisteredSender(socket);
  const storyId = String(message.storyId || "").trim();
  const story = viewerId && storyId ? await getStoryRecord(storyId) : null;
  if (!story || !story.encryptedKeys?.[viewerId]) {
    send(socket, { type: "story-share-result", requestId: String(message.requestId || ""), ok: false, message: "That story is no longer available." });
    return;
  }
  const recipients = Math.max(1, Math.min(100, Number(message.recipients) || 1));
  const shareCount = await addStoryShares(storyId, recipients, story);
  if (story.ownerId !== viewerId) sendToClient(story.ownerId, { type: "story-shared", storyId, shares: recipients, shareCount });
  send(socket, { type: "story-share-result", requestId: String(message.requestId || ""), ok: true, shareCount });
}

async function deleteStory(socket, message = {}) {
  const ownerId = getRegisteredSender(socket);
  const storyId = String(message.storyId || "").trim();
  const story = ownerId && storyId ? await getStoryRecord(storyId) : null;
  if (!story || story.ownerId !== ownerId) {
    send(socket, { type: "story-delete-result", requestId: String(message.requestId || ""), ok: false, message: "Story not found." });
    return;
  }
  const viewers = Object.keys(story.encryptedKeys || {});
  await removeStoryRecord(story);
  for (const viewerId of viewers) sendToClient(viewerId, { type: "story-deleted", storyId, ownerId });
  send(socket, { type: "story-delete-result", requestId: String(message.requestId || ""), ok: true, storyId });
}

// Removes a browser session from the online directory without deleting its persisted public key.
function unregisterClient(socket) {
  if (!socket.bypassiumId) return;
  const disconnectedId = socket.bypassiumId;
  const sockets = clients.get(socket.bypassiumId);
  if (sockets) {
    sockets.delete(socket);
    if (sockets.size === 0) {
      clients.delete(socket.bypassiumId);
      leaveAllGroupCalls(disconnectedId, "Disconnected from the call.");
    }
  }
  socket.bypassiumId = null;
}

// Reports which saved contacts are online and returns public keys known to the server.
async function sendContactStatuses(socket, contacts = []) {
  const statuses = {};
  const knownKeys = {};
  const profiles = {};
  const watcherId = getRegisteredSender(socket);
  socket.watchedContacts = new Set();
  const contactIds = [];
  for (const rawContactId of contacts) {
    const contactId = String(rawContactId || "").trim();
    if (!/^\d{6}$/.test(contactId) || socket.watchedContacts.has(contactId)) continue;
    socket.watchedContacts.add(contactId);
    contactIds.push(contactId);
  }
  await Promise.all(contactIds.map(async (contactId) => {
    let canSeePresence = true;
    if (watcherId && watcherId !== contactId) {
      const targetContacts = await getSyncedContacts(contactId);
      const watcher = targetContacts.find((contact) => contact.id === watcherId);
      canSeePresence = watcher?.sharePresence !== false;
    }
    statuses[contactId] = canSeePresence && clients.has(contactId) ? "online" : "offline";
    const publicKeyJwk = await getPublicKey(contactId);
    if (publicKeyJwk) knownKeys[contactId] = publicKeyJwk;
    const profile = await getProfile(contactId);
    if (profile) profiles[contactId] = profile;
  }));
  send(socket, { type: "contact-statuses", statuses, publicKeys: knownKeys, profiles });
}

// Stores the caller's contact list so the same account can restore contacts on another device.
async function syncContacts(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const incoming = sanitizeSyncedContacts(message.contacts, peerId);
  const existing = await getSyncedContacts(peerId);
  const contacts = mergeSyncedContacts(existing, incoming);
  await setSyncedContacts(peerId, contacts);
  send(socket, {
    type: "contact-sync",
    contacts,
    syncedAt: new Date().toISOString()
  });
}

async function sendSyncedContacts(socket, providedContacts = null) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const contacts = Array.isArray(providedContacts) ? providedContacts : await getSyncedContacts(peerId);
  send(socket, {
    type: "contact-sync",
    contacts,
    syncedAt: new Date().toISOString()
  });
}

// Removes a contact from the server-side contact list when a user deletes it locally.
async function deleteSyncedContact(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const contactId = String(message.contactId || "").trim();
  if (!/^\d{6}$/.test(contactId) || contactId === peerId) return;
  const contacts = (await getSyncedContacts(peerId)).filter((contact) => contact.id !== contactId);
  await setSyncedContacts(peerId, contacts);
  send(socket, {
    type: "contact-sync",
    contacts,
    deletedContactId: contactId,
    syncedAt: new Date().toISOString()
  });
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
  const accountBlock = await accountBlockInfo(peerId, "account");
  if (accountBlock) {
    sendAccountResponse(socket, message, false, accountBlock.message, accountBlock);
    return;
  }
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
  const existingProfile = await getProfile(peerId);
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
    profile: sanitizeProfile({ ...(existingProfile || {}), ...(message.profile || {}), badge: existingProfile?.badge || "" }),
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
  void recordSafetyLog("account-created", peerId, { remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
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
  const accountBlock = await accountBlockInfo(peerId, "account");
  if (accountBlock) {
    sendAccountResponse(socket, message, false, accountBlock.message, accountBlock);
    return;
  }
  if (!account?.passwordHash || !verifyPassword(password, account)) {
    void recordSafetyLog("failed-sign-in", peerId, { reason: "bad-credentials", remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
    sendAccountResponse(socket, message, false, "Code or password is incorrect.");
    return;
  }
  const sessionToken = issueSession(peerId);
  void recordSafetyLog("sign-in", peerId, { remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
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
  const accountBlock = await accountBlockInfo(peerId, "account");
  if (accountBlock) {
    sendAccountResponse(socket, message, false, accountBlock.message, accountBlock);
    return;
  }
  if (!account?.passwordHash || !(await validSession(peerId, sessionToken))) {
    void recordSafetyLog("failed-session-sign-in", peerId, { reason: "expired-session", remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
    sendAccountResponse(socket, message, false, "Saved sign-in expired. Enter your password once to trust this device again.");
    return;
  }
  void recordSafetyLog("session-sign-in", peerId, { remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
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
  const accountBlock = await accountBlockInfo(peerId, "account", { allowForcedReset: true });
  if (accountBlock) {
    sendAccountResponse(socket, message, false, accountBlock.message, accountBlock);
    return;
  }
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
  void recordSafetyLog("password-changed", peerId, { remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
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
  const accountBlock = await accountBlockInfo(peerId, "account", { allowForcedReset: true });
  if (accountBlock) {
    sendAccountResponse(socket, message, false, accountBlock.message, accountBlock);
    return;
  }
  if (!account?.recoveryHash || !verifyRecoveryPhrase(recoveryPhrase, account)) {
    void recordSafetyLog("failed-recovery", peerId, { reason: "bad-recovery-phrase", remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
    sendAccountResponse(socket, message, false, "Code or recovery phrase is incorrect.");
    return;
  }
  void recordSafetyLog("recovery-accepted", peerId, { remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
  sendAccountResponse(socket, message, true, "Recovery phrase accepted.", {
    account: publicAccountStatus(account, true),
    encryptedRecoveryBackup: account.encryptedRecoveryBackup || null
  });
}

async function checkOwnerResetCode(socket, message = {}) {
  if (!allowUserAction(socket, "account-recovery")) return;
  const resetCode = normalizeOwnerResetCode(message.resetCode);
  const requestedPeerId = cleanPeerId(message.peerId);
  if (!validOwnerResetCode(resetCode)) {
    sendAccountResponse(socket, message, false, "Owner reset code is invalid or incomplete.");
    return;
  }

  const peerId = requestedPeerId || await findPeerIdForOwnerResetCode(resetCode);
  if (!peerId || !(await verifyOwnerResetCode(peerId, resetCode))) {
    sendAccountResponse(socket, message, false, "Owner reset code is incorrect or expired.");
    return;
  }

  const account = await getAccount(peerId);
  if (!account?.passwordHash) {
    sendAccountResponse(socket, message, false, "That account cannot be reset with this code.");
    return;
  }
  const block = await accountBlockInfo(peerId, "account", { allowForcedReset: true });
  if (block && block.code === "account-banned") {
    sendAccountResponse(socket, message, false, block.message, block);
    return;
  }
  const ownerReset = await getOwnerResetRecord(peerId);
  sendAccountResponse(socket, message, true, "Owner reset code accepted.", {
    peerId,
    resetCode,
    expiresAt: ownerReset?.expiresAt || "",
    account: publicAccountStatus(account, true)
  });
}

async function resetPasswordWithRecovery(socket, message = {}) {
  const peerId = String(message.peerId || "").trim();
  const recoveryPhrase = normalizeRecoveryPhrase(message.recoveryPhrase);
  const password = String(message.password || "");
  const encryptedIdentityBackup = sanitizeEncryptedBackup(message.encryptedIdentityBackup);
  const publicKeyJwk = message.publicKeyJwk || null;
  const account = /^\d{6}$/.test(peerId) ? await getAccount(peerId) : null;
  const accountBlock = await accountBlockInfo(peerId, "account", { allowForcedReset: true });
  if (accountBlock) {
    sendAccountResponse(socket, message, false, accountBlock.message, accountBlock);
    return;
  }
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
  await setAccountRestriction(peerId, { passwordResetRequired: false });
  await setPublicKey(peerId, publicKeyJwk);
  const sessionToken = issueSession(peerId);
  void recordSafetyLog("password-reset-recovery", peerId, { remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
  sendAccountResponse(socket, message, true, "Password reset.", {
    sessionToken,
    account: publicAccountStatus(updated, true),
    encryptedIdentityBackup: updated.encryptedIdentityBackup || null
  });
}

async function resetPasswordWithOwnerCode(socket, message = {}) {
  const peerId = String(message.peerId || "").trim();
  const resetCode = String(message.resetCode || "").trim();
  const password = String(message.password || "");
  const encryptedIdentityBackup = sanitizeEncryptedBackup(message.encryptedIdentityBackup);
  const publicKeyJwk = message.publicKeyJwk || null;
  const account = /^\d{6}$/.test(peerId) ? await getAccount(peerId) : null;
  const accountBlock = await accountBlockInfo(peerId, "account", { allowForcedReset: true });
  if (accountBlock) {
    sendAccountResponse(socket, message, false, accountBlock.message, accountBlock);
    return;
  }
  if (!account?.passwordHash || !(await verifyOwnerResetCode(peerId, resetCode))) {
    sendAccountResponse(socket, message, false, "Owner reset code is incorrect or expired.");
    return;
  }
  if (!validPassword(password) || !encryptedIdentityBackup?.data || !publicKeyJwk) {
    sendAccountResponse(socket, message, false, "Choose a valid new password first.");
    return;
  }

  await revokePeerSessions(peerId);
  await consumeOwnerResetCode(peerId);
  const updated = sanitizeAccount({
    ...account,
    ...hashPassword(password),
    publicKeyJwk,
    encryptedIdentityBackup,
    updatedAt: new Date().toISOString()
  });
  await setAccount(peerId, updated);
  await setPublicKey(peerId, publicKeyJwk);
  await setAccountRestriction(peerId, { passwordResetRequired: false });
  const sessionToken = issueSession(peerId);
  void recordSafetyLog("password-reset-owner-code", peerId, { remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
  sendAccountResponse(socket, message, true, "Password reset by owner code.", {
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
  void recordSafetyLog("account-deleted-by-owner", peerId, { remoteAddress: socket.remoteAddress }).catch((error) => console.error("Safety log write failed:", error.message));
  sendAccountResponse(socket, message, true, "Account deleted.");
}

// Relays encrypted message envelopes or queues them until the receiver reconnects.
async function relayDirectMessage(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  if (!(await enforceAccountAction(socket, senderId, "send"))) return;
  if (!allowUserAction(socket, "message")) return;
  if (!validateContentType(socket, message)) return;

  const targetId = String(message.to || "").trim();
  if (!/^\d{6}$/.test(targetId) || !message.encrypted) {
    send(socket, { type: "message-error", messageId: String(message.messageId || ""), peerId: targetId, message: "Message target or encrypted payload is invalid." });
    return;
  }

  const messageId = message.messageId || randomUUID();
  let attachmentTransaction = null;
  try {
    attachmentTransaction = await reserveAttachmentCharge(senderId, messageId, message.attachmentBytes, message.contentType);
  } catch (error) {
    send(socket, { type: "message-error", messageId, peerId: targetId, message: error.message });
    return;
  }
  const envelope = {
    type: "direct-message",
    messageId,
    from: senderId,
    to: targetId,
    profile: localProfile(senderId),
    publicKeyJwk: socket.publicKeyJwk,
    encrypted: message.encrypted,
    sentAt: message.sentAt || new Date().toISOString(),
    contentType: String(message.contentType || "text").slice(0, 40),
    attachmentBytes: Math.max(0, Math.round(Number(message.attachmentBytes) || 0)),
    attachmentTransactionId: attachmentTransaction?.transactionId || ""
  };
  const targets = clients.get(targetId);
  const persistence = Promise.all([
    storeDirectMessageHistory(senderId, targetId, envelope, {
      senderEncrypted: message.senderEncrypted
    }),
    queueForDelivery(targetId, envelope, { awaitWrite: true })
  ]);
  if (!targets?.size) {
    try { await persistence; }
    catch (error) {
      await refundAttachmentCharge(envelope.attachmentTransactionId, "The attachment could not be stored.");
      throw error;
    }
    if (attachmentTransaction) await notifyWalletUpdated(senderId, attachmentTransaction);
    send(socket, {
      type: "message-status",
      messageId: envelope.messageId,
      peerId: targetId,
      status: "queued",
      updatedAt: new Date().toISOString()
    });
    send(socket, {
      type: "message-queued",
      messageId: envelope.messageId,
      peerId: targetId,
      sentAt: envelope.sentAt,
      persistent: storageMode() !== "memory"
    });
    return;
  }

  for (const target of targets) {
    if (target !== socket && target.readyState === 1) send(target, envelope);
  }
  // The recipient sees the live event immediately, while the sender only gets
  // a success state after the durable inbox and history copies are committed.
  try { await persistence; }
  catch (error) {
    await refundAttachmentCharge(envelope.attachmentTransactionId, "The attachment could not be stored.");
    throw error;
  }
  if (attachmentTransaction) await notifyWalletUpdated(senderId, attachmentTransaction);
  send(socket, {
    type: "message-status",
    messageId: envelope.messageId,
    peerId: targetId,
    status: "sent",
    updatedAt: new Date().toISOString()
  });
  send(socket, { type: "message-relayed", messageId: envelope.messageId, peerId: targetId, sentAt: envelope.sentAt });
}

// Relays an encrypted per-conversation setting without adding it to chat history.
async function relayDirectSetting(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  if (!(await enforceAccountAction(socket, senderId, "send"))) return;
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
  if (!targets?.size) queueForDelivery(targetId, envelope);
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
  if (!(await enforceAccountAction(socket, senderId, "send"))) return;
  if (!allowUserAction(socket, "group-message")) return;
  if (!validateContentType(socket, message)) return;
  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(senderId)) {
    send(socket, { type: "message-error", messageId: String(message.messageId || ""), groupId: String(message.groupId || ""), message: "You are not a member of this group." });
    return;
  }
  const recipients = Array.isArray(message.recipients) ? message.recipients : [];
  const sentAt = message.sentAt || new Date().toISOString();
  const messageId = message.messageId || randomUUID();
  let attachmentTransaction = null;
  try {
    attachmentTransaction = await reserveAttachmentCharge(senderId, messageId, message.attachmentBytes, message.contentType);
  } catch (error) {
    send(socket, { type: "message-error", messageId, groupId: String(message.groupId || ""), message: error.message });
    return;
  }
  const senderProfile = localProfile(senderId);
  const senderEncrypted = message.senderEncrypted;
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
      to: targetId,
      profile: senderProfile,
      publicKeyJwk: socket.publicKeyJwk,
      encrypted: recipient.encrypted,
      sentAt,
      contentType: String(message.contentType || "text").slice(0, 40),
      attachmentBytes: Math.max(0, Math.round(Number(message.attachmentBytes) || 0)),
      attachmentTransactionId: attachmentTransaction?.transactionId || ""
    };
    const targets = clients.get(targetId);
    if (targets?.size) {
      for (const target of targets) {
        if (target !== socket && target.readyState === 1) send(target, envelope);
      }
    }
    await queueForDelivery(targetId, envelope, { awaitWrite: true });
    return targetId;
  });
  let deliveryResults;
  try {
    [deliveryResults] = await Promise.all([
      Promise.all(deliveries),
      storeGroupMessageHistory(senderId, group, {
      messageId,
      sentAt,
      senderProfile,
      senderPublicKeyJwk: socket.publicKeyJwk,
      senderEncrypted,
      recipients
      })
    ]);
  } catch (error) {
    await refundAttachmentCharge(attachmentTransaction?.transactionId, "The group attachment could not be stored.");
    throw error;
  }
  const deliveredTo = deliveryResults.filter(Boolean);
  if (!deliveredTo.length) {
    await refundAttachmentCharge(attachmentTransaction?.transactionId, "No group recipient could receive this attachment.");
    send(socket, { type: "message-error", messageId, groupId: group.id, message: "No group member was ready to receive this attachment." });
    return;
  }
  if (attachmentTransaction) await notifyWalletUpdated(senderId, attachmentTransaction);
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
    const settledCharge = await settleAttachmentCharge(envelope);
    if (settledCharge?.senderId) await notifyWalletUpdated(settledCharge.senderId, settledCharge);
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

async function relayCallSignal(socket, message) {
  const senderId = getRegisteredSender(socket);
  if (!senderId) return;
  if (!(await enforceAccountAction(socket, senderId, "send"))) return;
  if (!allowUserAction(socket, "message")) return;

  const targetId = String(message.to || "").trim();
  const callId = String(message.callId || "").trim().slice(0, 80);
  const groupId = String(message.groupId || "").trim().slice(0, 120);
  const action = String(message.action || "").trim();
  const allowedActions = new Set([
    "ring",
    "invite",
    "answer",
    "candidate",
    "renegotiate-offer",
    "renegotiate-answer",
    "media-state",
    "end",
    "decline",
    "cancel",
    "busy",
    "unavailable"
  ]);
  if (!/^\d{6}$/.test(targetId) || !callId || !allowedActions.has(action)) {
    send(socket, { type: "error", message: "Call signal target or action is invalid." });
    return;
  }

  if (groupId) {
    const room = groupCallRooms.get(callId);
    if (!room || room.groupId !== groupId || !room.joined.has(senderId) || !room.joined.has(targetId)) {
      send(socket, { type: "error", message: "That group call participant is no longer available." });
      return;
    }
  }

  const description = sanitizeCallDescription(message.description);
  const candidate = sanitizeCallCandidate(message.candidate);
  if ((message.description && !description) || (message.candidate && !candidate)) {
    send(socket, { type: "error", message: "Call signal payload is too large or invalid." });
    return;
  }

  const envelope = {
    type: "call-signal",
    callId,
    groupId,
    action,
    from: senderId,
    profile: localProfile(senderId),
    description,
    candidate,
    media: sanitizeCallMediaState(message.media),
    reason: String(message.reason || "").slice(0, 140),
    sentAt: new Date().toISOString()
  };

  let billingSession = groupId ? null : await getCallBilling(callId);
  if (!groupId && ["ring", "invite"].includes(action)) {
    if (!billingSession) billingSession = await ensureCallBilling(senderId, targetId, callId);
    if (!billingSession.participants.has(senderId) || !billingSession.participants.has(targetId)) return;
    envelope.billing = publicCallBilling(billingSession);
  }

  const targets = clients.get(targetId);
  if (!targets?.size) {
    if (billingSession) await finishCallBilling(billingSession, "Contact was offline");
    send(socket, {
      type: "call-signal",
      callId,
      groupId,
      action: "unavailable",
      from: targetId,
      reason: "That contact is not online for calls.",
      sentAt: envelope.sentAt
    });
    return;
  }

  let delivered = 0;
  for (const target of targets) {
    if (target !== socket && target.readyState === 1) {
      send(target, envelope);
      delivered += 1;
    }
  }
  if (!delivered) {
    if (billingSession) await finishCallBilling(billingSession, "Call could not be delivered");
    send(socket, {
      type: "call-signal",
      callId,
      groupId,
      action: "unavailable",
      from: targetId,
      reason: "That contact is already connected from this browser only.",
      sentAt: envelope.sentAt
    });
    return;
  }
  if (billingSession && action === "answer" && !billingSession.connectedAt) {
    billingSession.connectedAt = Date.now();
    billingSession.lastTickAt = billingSession.connectedAt;
    await saveCallBilling(billingSession);
    broadcastCallBilling(billingSession);
  }
  if (billingSession && ["end", "decline", "cancel", "busy", "unavailable"].includes(action)) {
    await finishCallBilling(billingSession, action === "end" ? "Call ended" : "Call was not accepted");
  }
}

// Creates a short-lived group call room. Audio and video remain peer-to-peer.
async function startGroupCall(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!(await enforceAccountAction(socket, peerId, "send"))) return;
  if (!allowUserAction(socket, "message")) return;
  cleanupStaleGroupCalls();

  const group = await getGroup(message.groupId);
  if (!group || !group.members.includes(peerId)) {
    sendGroupCallResult(socket, message, false, "Only members of this group can start its call.");
    return;
  }
  if (group.members.length > MAX_GROUP_CALL_MEMBERS) {
    sendGroupCallResult(socket, message, false, `Group calls currently support up to ${MAX_GROUP_CALL_MEMBERS} people.`);
    return;
  }

  let room = activeGroupCallForGroup(group.id);
  const created = !room;
  let billing = room ? await getCallBilling(room.billingCallId || room.callId) : null;
  if (!room) {
    const callId = cleanGroupCallId(message.callId) || randomUUID();
    try {
      billing = await ensureGroupCallBilling(peerId, group, callId);
    } catch (error) {
      sendGroupCallResult(socket, message, false, error.message || "The group call could not be funded.");
      return;
    }
    room = {
      callId,
      groupId: group.id,
      startedBy: peerId,
      joined: new Set(),
      createdAt: Date.now(),
      billingCallId: billing.callId
    };
    groupCallRooms.set(callId, room);
  }

  const peers = joinGroupCallRoom(room, peerId);
  if (created) {
    const invite = {
      type: "group-call-invite",
      callId: room.callId,
      groupId: group.id,
      from: peerId,
      profile: localProfile(peerId),
      group: publicGroupCallGroup(group),
      sentAt: new Date().toISOString(),
      billing: publicCallBilling(billing)
    };
    for (const memberId of group.members) {
      if (memberId !== peerId) sendToClient(memberId, invite);
    }
  }

  const roomBilling = await getCallBilling(room.billingCallId || room.callId);
  send(socket, {
    type: "group-call-started",
    requestId: String(message.requestId || ""),
    ok: true,
    callId: room.callId,
    groupId: room.groupId,
    existing: !created,
    peers: groupCallPeerList(peers),
    billing: roomBilling ? publicCallBilling(roomBilling) : null
  });
}

// Adds a member to a room and announces them to the existing mesh.
async function joinGroupCall(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  cleanupStaleGroupCalls();
  const callId = cleanGroupCallId(message.callId);
  const room = groupCallRooms.get(callId);
  const group = room ? await getGroup(room.groupId) : null;
  if (!room || !group || group.id !== String(message.groupId || "").trim() || !group.members.includes(peerId)) {
    sendGroupCallResult(socket, message, false, "That group call has ended or you are not a member.");
    return;
  }
  if (group.members.length > MAX_GROUP_CALL_MEMBERS) {
    sendGroupCallResult(socket, message, false, `Group calls currently support up to ${MAX_GROUP_CALL_MEMBERS} people.`);
    return;
  }
  const peers = joinGroupCallRoom(room, peerId);
  const billing = await getCallBilling(room.billingCallId || room.callId);
  if (billing && !billing.connectedAt && peers.length) {
    billing.connectedAt = Date.now();
    billing.lastTickAt = billing.connectedAt;
    await saveCallBilling(billing);
    broadcastCallBilling(billing);
  }
  send(socket, {
    type: "group-call-joined",
    requestId: String(message.requestId || ""),
    ok: true,
    callId: room.callId,
    groupId: room.groupId,
    peers: groupCallPeerList(peers),
    billing: billing ? publicCallBilling(billing) : null
  });
}

// Removes a participant immediately and destroys the room when it becomes empty.
async function leaveGroupCall(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const room = groupCallRooms.get(cleanGroupCallId(message.callId));
  if (room && room.groupId === String(message.groupId || "").trim()) {
    removeGroupCallPeer(room, peerId, String(message.reason || "Left the call.").slice(0, 140));
  }
  if (message.requestId) send(socket, { type: "group-call-left", requestId: String(message.requestId), ok: true });
}

function joinGroupCallRoom(room, peerId) {
  const peers = [...room.joined].filter((id) => id !== peerId);
  const wasJoined = room.joined.has(peerId);
  room.joined.add(peerId);
  if (!wasJoined) {
    for (const existingPeerId of peers) {
      sendToClient(existingPeerId, {
        type: "group-call-peer-joined",
        callId: room.callId,
        groupId: room.groupId,
        peerId,
        profile: localProfile(peerId)
      });
    }
  }
  return peers;
}

function removeGroupCallPeer(room, peerId, reason = "Left the call.") {
  if (!room?.joined.delete(peerId)) return;
  for (const existingPeerId of room.joined) {
    sendToClient(existingPeerId, {
      type: "group-call-peer-left",
      callId: room.callId,
      groupId: room.groupId,
      peerId,
      reason
    });
  }
  if (!room.joined.size) {
    groupCallRooms.delete(room.callId);
    void getCallBilling(room.billingCallId || room.callId).then((billing) => finishCallBilling(billing, "Group call ended")).catch(() => {});
  }
}

function leaveAllGroupCalls(peerId, reason) {
  for (const room of [...groupCallRooms.values()]) removeGroupCallPeer(room, peerId, reason);
}

function activeGroupCallForGroup(groupId) {
  return [...groupCallRooms.values()].find((room) => room.groupId === groupId) || null;
}

function cleanupStaleGroupCalls() {
  const cutoff = Date.now() - GROUP_CALL_TTL_MS;
  for (const room of [...groupCallRooms.values()]) {
    if (room.createdAt >= cutoff) continue;
    for (const peerId of room.joined) {
      sendToClient(peerId, {
        type: "group-call-ended",
        callId: room.callId,
        groupId: room.groupId,
        reason: "The group call expired."
      });
    }
    groupCallRooms.delete(room.callId);
  }
}

function cleanGroupCallId(value) {
  const callId = String(value || "").trim().slice(0, 80);
  return /^[A-Za-z0-9_-]{8,80}$/.test(callId) ? callId : "";
}

function publicGroupCallGroup(group) {
  return {
    id: group.id,
    name: String(group.name || "Group call").slice(0, 80),
    avatar: sanitizeProfilePicture(group.avatar),
    members: normalizeMembers(group.members || [])
  };
}

function groupCallPeerList(peerIds) {
  return peerIds.map((peerId) => ({ peerId, profile: localProfile(peerId) }));
}

function sendGroupCallResult(socket, message, ok, responseMessage) {
  send(socket, {
    type: "group-call-result",
    requestId: String(message.requestId || ""),
    ok,
    message: responseMessage
  });
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

// Persists the user's own conversation read position and mirrors it to their
// other connected devices without exposing message contents.
async function relayReadState(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  const groupId = String(message.groupId || "").trim();
  const contactId = String(message.contactId || "").trim();
  let conversationKey = "";
  if (groupId) {
    const group = await getGroup(groupId);
    if (!group?.members.includes(peerId)) return;
    conversationKey = `group:${groupId}`;
  } else if (/^\d{6}$/.test(contactId) && contactId !== peerId) {
    conversationKey = `direct:${contactId}`;
  }
  if (!conversationKey) return;
  const candidate = new Date(message.readAt || Date.now());
  if (!Number.isFinite(candidate.getTime())) return;
  const readAt = candidate.toISOString();
  await setConversationReadState(peerId, conversationKey, readAt);
  const envelope = {
    type: "read-state-sync",
    groupId,
    contactId,
    readAt
  };
  for (const target of clients.get(peerId) || []) {
    if (target !== socket && target.readyState === 1) send(target, envelope);
  }
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
  if (!(await enforceAccountAction(socket, peerId, "account"))) return;
  const existing = await getProfile(peerId);
  const cleanProfile = sanitizeProfile({
    ...profile,
    joinedAt: existing?.joinedAt || new Date().toISOString(),
    badge: existing?.badge || ""
  }, true);
  await setProfile(peerId, cleanProfile);
  const account = await getAccount(peerId);
  if (account) await setAccount(peerId, { ...account, profile: cleanProfile, updatedAt: new Date().toISOString() });
  if (await accountQuickAddHidden(peerId)) await removeQuickAddProfile(peerId);
  else await updateQuickAddDirectory(peerId, cleanProfile);
  void recordSafetyLog("profile-updated", peerId, {
    displayNameChanged: existing?.displayName !== cleanProfile.displayName,
    profilePictureChanged: existing?.profilePicture !== cleanProfile.profilePicture
  }).catch((error) => console.error("Safety log write failed:", error.message));
  broadcastProfileUpdate(peerId, cleanProfile);
}

// Returns a paginated, sanitized directory of customized public profiles.
async function sendQuickAddResults(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!(await enforceAccountAction(socket, peerId, "quick-add"))) return;
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
    if (await accountQuickAddHidden(id)) continue;
    if (!isDiscoverableProfile(profile)) continue;
    if (query && !String(profile.displayName || "").toLowerCase().includes(query) && !id.includes(query)) continue;
    matches.push({
      id,
      displayName: profile.displayName || "Bypassium User",
      profilePicture: profile.profilePicture,
      badge: profile.badge || "",
      joinedAt: profile.joinedAt || profile.updatedAt || "",
      status: clients.has(id) ? "online" : "offline",
      statusText: activeProfileStatus(profile).text,
      statusExpiresAt: activeProfileStatus(profile).expiresAt
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

  if (!accountIndexHydrated) scheduleAccountIndexHydration();
  let entries = await getAccountSearchEntries();
  if (!entries.length) entries = await getQuickAddDirectoryEntries();
  const matches = [];
  for (const { id, profile } of entries) {
    if (!isDiscoverableProfile(profile) && !id.includes(query)) continue;
    const score = accountSearchScore(query, id, profile.displayName || "");
    if (score === null) continue;
    matches.push({
      id,
      displayName: profile.displayName || "Bypassium User",
      profilePicture: profile.profilePicture,
      badge: profile.badge || "",
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
  if (!(await enforceAccountAction(socket, creatorId, "groups"))) return;
  if (!allowUserAction(socket, "group-manage")) return;
  const requestedMembers = normalizeMembers([creatorId, ...(message.members || [])]);
  const members = [];
  for (const memberId of requestedMembers) {
    if (memberId === creatorId || !(await accountGroupsDisabled(memberId))) members.push(memberId);
  }
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
  void recordSafetyLog("group-created", creatorId, { groupId: group.id, memberCount: members.length }).catch((error) => console.error("Safety log write failed:", error.message));
  broadcastGroupUpdate(group);
}

async function renameGroup(socket, message) {
  return updateGroupDetails(socket, message);
}

async function updateGroupDetails(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!(await enforceAccountAction(socket, peerId, "groups"))) return;
  if (!allowUserAction(socket, "group-manage")) return;
  const group = await getGroup(message.groupId);
  if (!group || !canAdministerGroup(group, peerId)) {
    send(socket, { type: "error", message: "Only the group owner or an administrator can change group details." });
    return;
  }
  const previous = { name: group.name, avatar: group.avatar, memberAddLocked: Boolean(group.memberAddLocked) };
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
  void recordSafetyLog("group-updated", peerId, {
    groupId: group.id,
    nameChanged: previous.name !== group.name,
    avatarChanged: previous.avatar !== group.avatar,
    memberAddLockedChanged: previous.memberAddLocked !== Boolean(group.memberAddLocked)
  }).catch((error) => console.error("Safety log write failed:", error.message));
  broadcastGroupUpdate(group);
}

async function addGroupMembers(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!(await enforceAccountAction(socket, peerId, "groups"))) return;
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
  const requestedMembers = [];
  for (const memberId of normalizeMembers(message.members || [])) {
    if (!(await accountGroupsDisabled(memberId))) requestedMembers.push(memberId);
  }
  const previousMembers = new Set(group.members);
  group.members = normalizeMembers([...group.members, ...requestedMembers]);
  group.updatedAt = new Date().toISOString();
  await setGroup(group);
  void recordSafetyLog("group-members-added", peerId, {
    groupId: group.id,
    added: group.members.filter((id) => !previousMembers.has(id))
  }).catch((error) => console.error("Safety log write failed:", error.message));
  broadcastGroupUpdate(group);
}

async function setGroupAdmin(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!(await enforceAccountAction(socket, peerId, "groups"))) return;
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
  void recordSafetyLog("group-admin-updated", peerId, { groupId: group.id, memberId, isAdmin: message.isAdmin !== false }).catch((error) => console.error("Safety log write failed:", error.message));
  broadcastGroupUpdate(group);
}

async function transferGroupOwnership(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!(await enforceAccountAction(socket, peerId, "groups"))) return;
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
  void recordSafetyLog("group-owner-transferred", peerId, { groupId: group.id, newOwnerId: memberId }).catch((error) => console.error("Safety log write failed:", error.message));
  broadcastGroupUpdate(group);
}

async function removeGroupMember(socket, message) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  if (!(await enforceAccountAction(socket, peerId, "groups"))) return;
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
  void recordSafetyLog("group-member-removed", peerId, { groupId: group.id, memberId }).catch((error) => console.error("Safety log write failed:", error.message));
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
    void recordSafetyLog("group-left", peerId, { groupId: group.id }).catch((error) => console.error("Safety log write failed:", error.message));
    broadcastGroupUpdate(group, [peerId]);
  } else {
    void recordSafetyLog("group-deleted-empty", peerId, { groupId: group.id }).catch((error) => console.error("Safety log write failed:", error.message));
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
      if (awaitWrite) throw error;
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
  const newestFirst = fresh.sort((first, second) => queuedEnvelopeTime(second) - queuedEnvelopeTime(first));
  for (let index = 0; index < newestFirst.length; index += OFFLINE_DELIVERY_BATCH_SIZE) {
    for (const message of newestFirst.slice(index, index + OFFLINE_DELIVERY_BATCH_SIZE)) send(socket, message);
    if (index + OFFLINE_DELIVERY_BATCH_SIZE < newestFirst.length) await yieldToSocketTraffic(BACKGROUND_DELIVERY_YIELD_MS);
  }
  for (const id of expiredIds) await removeOfflineMessage(socket.bypassiumId, id);
  if (legacyQueue.length) await deleteLegacyInbox(socket.bypassiumId);
}

async function getOfflineMessages(targetId) {
  if (!redis && !upstashRestEnabled) return memoryOfflineMessages.get(targetId) || [];
  const ids = await getInboxIds(targetId);
  const uniqueIds = [...new Set(ids)].slice(-maxOfflineMessagesPerUser());
  const storedValues = await getQueuedMessages(targetId, uniqueIds);
  const messages = [];
  const keptIds = [];
  for (const [index, id] of uniqueIds.entries()) {
    const stored = storedValues[index];
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

async function getQueuedMessages(targetId, messageIds = []) {
  const ids = messageIds.filter(Boolean);
  if (!ids.length) return [];
  if (redis) return redis.mget(ids.map((id) => queuedMessageKey(targetId, id)));
  if (upstashRestEnabled) return batchedUpstashGets(ids.map((id) => queuedMessageKey(targetId, id)));
  return ids.map(() => null);
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

async function storeDirectMessageHistory(senderId, targetId, envelope, { senderEncrypted = null } = {}) {
  const sentAt = envelope.sentAt || new Date().toISOString();
  const writes = [queueHistoryMessage(targetId, {
    type: "direct-message",
    historyKind: "direct",
    historyDirection: "inbound",
    historyPeerId: senderId,
    messageId: envelope.messageId,
    from: senderId,
    profile: envelope.profile,
    publicKeyJwk: envelope.publicKeyJwk,
    encrypted: envelope.encrypted,
    sentAt
  })];

  if (validEncryptedPayload(senderEncrypted)) {
    const [targetProfile, targetPublicKeyJwk] = await Promise.all([
      getProfile(targetId).then((profile) => profile || {}),
      getPublicKey(targetId)
    ]);
    writes.push(queueHistoryMessage(senderId, {
      type: "direct-message",
      historyKind: "direct",
      historyDirection: "outbound",
      historyPeerId: targetId,
      messageId: envelope.messageId,
      from: senderId,
      profile: targetProfile,
      peerProfile: targetProfile,
      publicKeyJwk: envelope.publicKeyJwk,
      peerPublicKeyJwk: targetPublicKeyJwk,
      encrypted: senderEncrypted,
      sentAt,
      selfEncrypted: true
    }));
  }
  await Promise.all(writes);
}

async function storeGroupMessageHistory(senderId, group, options = {}) {
  const messageId = String(options.messageId || "");
  if (!messageId) return;
  const sentAt = options.sentAt || new Date().toISOString();
  const recipientById = new Map((options.recipients || []).map((recipient) => [String(recipient.to || ""), recipient]));
  const senderPublicKeyJwk = options.senderPublicKeyJwk || null;

  const writes = [];
  for (const memberId of group.members || []) {
    if (memberId === senderId) continue;
    const recipient = recipientById.get(memberId);
    if (!validEncryptedPayload(recipient?.encrypted)) continue;
    writes.push(queueHistoryMessage(memberId, {
      type: "group-message",
      historyKind: "group",
      historyDirection: "inbound",
      historyPeerId: senderId,
      groupId: group.id,
      groupName: group.name,
      members: group.members,
      messageId,
      from: senderId,
      profile: options.senderProfile || {},
      publicKeyJwk: senderPublicKeyJwk,
      encrypted: recipient.encrypted,
      sentAt
    }));
  }

  if (validEncryptedPayload(options.senderEncrypted) && senderPublicKeyJwk) {
    writes.push(queueHistoryMessage(senderId, {
      type: "group-message",
      historyKind: "group",
      historyDirection: "outbound",
      historyPeerId: senderId,
      groupId: group.id,
      groupName: group.name,
      members: group.members,
      messageId,
      from: senderId,
      profile: options.senderProfile || {},
      publicKeyJwk: senderPublicKeyJwk,
      senderPublicKeyJwk,
      encrypted: options.senderEncrypted,
      sentAt,
      selfEncrypted: true
    }));
  }
  await Promise.all(writes);
}

async function queueHistoryMessage(peerId, entry) {
  const historyId = String(entry.historyId || `${entry.messageId}:${entry.historyDirection || "inbound"}:${entry.historyKind || entry.type}`);
  const payload = {
    ...entry,
    historyId,
    storedAt: Date.now()
  };
  const serialized = JSON.stringify(payload);
  if (serialized.length > MAX_QUEUED_ENVELOPE_CHARS) return;
  const storageLimit = maxHistoryMessagesPerUser();
  if (!redis && !upstashRestEnabled) {
    const history = memoryHistoryMessages.get(peerId) || [];
    const next = history.filter((item) => item.historyId !== historyId);
    next.push(payload);
    memoryHistoryMessages.set(peerId, storageLimit > 0 ? next.slice(-storageLimit) : next);
    return;
  }

  const indexKey = historyIndexKey(peerId);
  const messageKey = historyMessageKey(peerId, historyId);
  const ttl = historyTtlSeconds();
  if (redis) {
    const pipeline = redis.pipeline();
    if (ttl > 0) pipeline.set(messageKey, serialized, "EX", ttl);
    else pipeline.set(messageKey, serialized);
    pipeline.lrem(indexKey, 0, historyId);
    pipeline.rpush(indexKey, historyId);
    if (storageLimit > 0) pipeline.ltrim(indexKey, -storageLimit, -1);
    if (ttl > 0) pipeline.expire(indexKey, ttl);
    await pipeline.exec();
    return;
  }

  const commands = [
    ttl > 0 ? ["SET", messageKey, serialized, "EX", ttl] : ["SET", messageKey, serialized],
    ["LREM", indexKey, 0, historyId],
    ["RPUSH", indexKey, historyId]
  ];
  if (storageLimit > 0) commands.push(["LTRIM", indexKey, -storageLimit, -1]);
  if (ttl > 0) commands.push(["EXPIRE", indexKey, ttl]);
  await upstashPipeline(commands);
}

async function deliverHistoryMessages(socket, limit = defaultHistorySyncLimit()) {
  const peerId = socket.bypassiumId;
  if (!peerId) return;
  const history = await annotateHistoryReadState(peerId, await getHistoryMessages(peerId, limit));
  if (history.length) await sendHistoryItems(socket, history);
  send(socket, {
    type: "history-sync-complete",
    count: history.length,
    syncedAt: new Date().toISOString()
  });
}

async function annotateHistoryReadState(peerId, history = []) {
  const conversationKeys = [...new Set(history
    .filter((item) => item.historyDirection === "inbound")
    .map((item) => item.historyKind === "group" ? `group:${item.groupId}` : `direct:${item.historyPeerId}`)
    .filter((key) => !key.endsWith(":")))];
  const states = new Map(await Promise.all(conversationKeys.map(async (key) => [
    key,
    await getConversationReadState(peerId, key)
  ])));
  return history.map((item) => {
    if (item.historyDirection !== "inbound") return item;
    const key = item.historyKind === "group" ? `group:${item.groupId}` : `direct:${item.historyPeerId}`;
    const readAt = states.get(key) || "";
    const messageTime = Date.parse(item.sentAt || "");
    return {
      ...item,
      readBySelf: Boolean(readAt && Number.isFinite(messageTime) && messageTime <= Date.parse(readAt)),
      selfReadAt: readAt
    };
  });
}

async function sendHistoryItems(socket, history) {
  let batch = [];
  for (const item of history) {
    const candidate = [...batch, item];
    const size = JSON.stringify({ type: "history-items", items: candidate }).length;
    if (batch.length && size > MAX_HISTORY_BATCH_CHARS) {
      send(socket, { type: "history-items", items: batch });
      await yieldToSocketTraffic();
      batch = [item];
    } else {
      batch = candidate;
    }
  }
  if (batch.length) send(socket, { type: "history-items", items: batch });
}

function queuedEnvelopeTime(message = {}) {
  const value = Date.parse(message.sentAt || message.queuedAt || "");
  return Number.isFinite(value) ? value : 0;
}

function yieldToSocketTraffic(delay = 0) {
  return new Promise((resolve) => setTimeout(resolve, delay));
}

async function setConversationReadState(peerId, conversationKey, readAt) {
  const key = conversationReadStateKey(peerId, conversationKey);
  const existing = await getConversationReadState(peerId, conversationKey);
  if (existing && Date.parse(existing) >= Date.parse(readAt)) return existing;
  memoryConversationReadStates.set(key, readAt);
  if (redis) await redis.set(key, readAt);
  else if (upstashRestEnabled) await upstashCommand(["SET", key, readAt]);
  return readAt;
}

async function getConversationReadState(peerId, conversationKey) {
  const key = conversationReadStateKey(peerId, conversationKey);
  if (memoryConversationReadStates.has(key)) return memoryConversationReadStates.get(key);
  let stored = "";
  if (redis) stored = await redis.get(key);
  else if (upstashRestEnabled) stored = await upstashCommand(["GET", key]);
  if (stored) memoryConversationReadStates.set(key, String(stored));
  return String(stored || "");
}

async function getHistoryMessages(peerId, limit = 500) {
  const requestedLimit = Math.max(0, Number(limit) || 0);
  if (!redis && !upstashRestEnabled) {
    const history = memoryHistoryMessages.get(peerId) || [];
    const limitedHistory = requestedLimit ? history.slice(-requestedLimit) : history;
    return newestHistoryFirst(limitedHistory);
  }
  const ids = await getHistoryIds(peerId);
  const allUniqueIds = [...new Set(ids)];
  const uniqueIds = requestedLimit ? allUniqueIds.slice(-requestedLimit) : allUniqueIds;
  const storedValues = await getHistoryMessageValues(peerId, uniqueIds);
  const messages = [];
  const keptIds = [];
  for (const [index, id] of uniqueIds.entries()) {
    const stored = storedValues[index];
    if (!stored) continue;
    try {
      messages.push(JSON.parse(stored));
      keptIds.push(id);
    } catch {
      await deleteHistoryMessage(peerId, id);
    }
  }
  if (!requestedLimit && keptIds.length !== allUniqueIds.length) await replaceHistoryIds(peerId, keptIds);
  return newestHistoryFirst(messages);
}

function newestHistoryFirst(messages = []) {
  return [...messages].sort((first, second) => historyMessageTime(second) - historyMessageTime(first));
}

function historyMessageTime(message = {}) {
  const parsed = Date.parse(message.sentAt || "");
  return Number.isFinite(parsed) ? parsed : 0;
}

async function getHistoryIds(peerId) {
  if (redis) return redis.lrange(historyIndexKey(peerId), 0, -1);
  if (upstashRestEnabled) return upstashCommand(["LRANGE", historyIndexKey(peerId), 0, -1]);
  return [];
}

async function getHistoryMessage(peerId, historyId) {
  if (redis) return redis.get(historyMessageKey(peerId, historyId));
  if (upstashRestEnabled) return upstashCommand(["GET", historyMessageKey(peerId, historyId)]);
  return null;
}

async function getHistoryMessageValues(peerId, historyIds = []) {
  const ids = historyIds.filter(Boolean);
  if (!ids.length) return [];
  if (redis) return redis.mget(ids.map((id) => historyMessageKey(peerId, id)));
  if (upstashRestEnabled) return batchedUpstashGets(ids.map((id) => historyMessageKey(peerId, id)));
  return ids.map(() => null);
}

async function deleteHistoryMessage(peerId, historyId) {
  if (redis) {
    await redis.del(historyMessageKey(peerId, historyId));
    return;
  }
  if (upstashRestEnabled) await upstashCommand(["DEL", historyMessageKey(peerId, historyId)]);
}

async function replaceHistoryIds(peerId, ids) {
  if (redis) {
    const key = historyIndexKey(peerId);
    await redis.del(key);
    if (ids.length) {
      await redis.rpush(key, ...ids);
      if (historyTtlSeconds() > 0) await redis.expire(key, historyTtlSeconds());
    }
    return;
  }
  if (upstashRestEnabled) {
    const key = historyIndexKey(peerId);
    await upstashCommand(["DEL", key]);
    if (ids.length) {
      await upstashPushList(key, ids);
      if (historyTtlSeconds() > 0) await upstashCommand(["EXPIRE", key, historyTtlSeconds()]);
    }
  }
}

async function deleteAllHistoryMessages(peerId) {
  memoryHistoryMessages.delete(peerId);
  const ids = await getHistoryIds(peerId);
  for (const id of new Set(ids)) await deleteHistoryMessage(peerId, id);
  if (redis) await redis.del(historyIndexKey(peerId));
  if (upstashRestEnabled) await upstashCommand(["DEL", historyIndexKey(peerId)]);
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
  void updateAccountIndex(peerId).catch((error) => console.error("Account index update failed:", error.message));
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
  await updateAccountIndex(peerId, clean.profile, clean);
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
  await removeAccountIndex(peerId);
}

async function setSyncedContacts(peerId, contacts = []) {
  const clean = sanitizeSyncedContacts(contacts, peerId);
  memoryContactLists.set(peerId, clean);
  if (redis) await redis.set(contactListKey(peerId), JSON.stringify(clean));
  if (upstashRestEnabled) await upstashCommand(["SET", contactListKey(peerId), JSON.stringify(clean)]);
}

async function getSyncedContacts(peerId) {
  if (memoryContactLists.has(peerId)) return memoryContactLists.get(peerId);
  let stored = null;
  if (redis) stored = await redis.get(contactListKey(peerId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", contactListKey(peerId)]);
  if (!stored) return [];
  const contacts = sanitizeSyncedContacts(JSON.parse(stored), peerId);
  memoryContactLists.set(peerId, contacts);
  return contacts;
}

// Stories expire after 24 hours; Reels remain available for a longer creator
// library window while retaining the same encrypted content envelope.
function contentRecordTtlSeconds(record = {}) {
  return ["reel", "highlight"].includes(record.contentKind) ? REEL_TTL_SECONDS : STORY_TTL_SECONDS;
}

async function removeSyncedContacts(peerId) {
  memoryContactLists.delete(peerId);
  if (redis) await redis.del(contactListKey(peerId));
  if (upstashRestEnabled) await upstashCommand(["DEL", contactListKey(peerId)]);
}

async function setStoryRecord(record) {
  memoryStories.set(record.storyId, record);
  const expiresAtMs = Date.parse(record.expiresAt);
  const ttl = contentRecordTtlSeconds(record);
  for (const viewerId of Object.keys(record.encryptedKeys || {})) {
    if (!memoryStoryIndexes.has(viewerId)) memoryStoryIndexes.set(viewerId, new Set());
    memoryStoryIndexes.get(viewerId).add(record.storyId);
  }
  const serialized = JSON.stringify(record);
  if (redis) {
    const pipeline = redis.multi();
    pipeline.set(storyKey(record.storyId), serialized, "EX", ttl);
    for (const viewerId of Object.keys(record.encryptedKeys || {})) {
      pipeline.zadd(storyIndexKey(viewerId), expiresAtMs, record.storyId);
      pipeline.expire(storyIndexKey(viewerId), ttl + 300);
    }
    pipeline.zadd(storyOwnerIndexKey(record.ownerId), expiresAtMs, record.storyId);
    pipeline.expire(storyOwnerIndexKey(record.ownerId), ttl + 300);
    await pipeline.exec();
  }
  if (upstashRestEnabled) {
    const commands = [["SET", storyKey(record.storyId), serialized, "EX", ttl]];
    for (const viewerId of Object.keys(record.encryptedKeys || {})) {
      commands.push(["ZADD", storyIndexKey(viewerId), expiresAtMs, record.storyId]);
      commands.push(["EXPIRE", storyIndexKey(viewerId), ttl + 300]);
    }
    commands.push(["ZADD", storyOwnerIndexKey(record.ownerId), expiresAtMs, record.storyId]);
    commands.push(["EXPIRE", storyOwnerIndexKey(record.ownerId), ttl + 300]);
    await upstashPipeline(commands);
  }
}

async function getStoryRecord(storyId) {
  const cached = memoryStories.get(storyId);
  if (cached && Date.parse(cached.expiresAt) > Date.now()) return refreshReelRetention(cached);
  let stored = null;
  if (redis) stored = await redis.get(storyKey(storyId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", storyKey(storyId)]);
  if (!stored) return null;
  const story = JSON.parse(stored);
  if (Date.parse(story.expiresAt) <= Date.now()) return null;
  memoryStories.set(storyId, story);
  return refreshReelRetention(story);
}

async function refreshReelRetention(story) {
  if (!story || !["reel", "highlight"].includes(story.contentKind)) return story;
  const refreshThreshold = Date.now() + 5 * 365 * 24 * 60 * 60 * 1000;
  if (Date.parse(story.expiresAt) >= refreshThreshold) return story;
  const refreshed = {
    ...story,
    expiresAt: new Date(Date.now() + REEL_TTL_SECONDS * 1000).toISOString()
  };
  await setStoryRecord(refreshed);
  return refreshed;
}

async function getStoriesForViewer(viewerId) {
  let ids = [];
  if (!redis && !upstashRestEnabled) ids = [...(memoryStoryIndexes.get(viewerId) || [])];
  if (redis) {
    await redis.zremrangebyscore(storyIndexKey(viewerId), 0, Date.now());
    ids = await redis.zrangebyscore(storyIndexKey(viewerId), Date.now(), "+inf");
  }
  if (upstashRestEnabled) {
    await upstashCommand(["ZREMRANGEBYSCORE", storyIndexKey(viewerId), 0, Date.now()]);
    ids = await upstashCommand(["ZRANGEBYSCORE", storyIndexKey(viewerId), Date.now(), "+inf"]);
  }
  const stories = [];
  const uniqueIds = [...new Set(ids)].slice(-MAX_SOCIAL_ITEMS_PER_VIEWER);
  for (let index = 0; index < uniqueIds.length; index += 12) {
    const batch = await Promise.all(uniqueIds.slice(index, index + 12).map(getStoryRecord));
    for (const story of batch) if (story?.encryptedKeys?.[viewerId]) stories.push(story);
  }
  return stories.sort((first, second) => Date.parse(first.createdAt) - Date.parse(second.createdAt));
}

async function storyEnvelopeForViewer(story, viewerId) {
  const encryptedKey = story?.encryptedKeys?.[viewerId];
  if (!encryptedKey) return null;
  const [allFeedback, ownerPublicKey, viewers, shareCount] = await Promise.all([
    getStoryFeedback(story.storyId),
    getPublicKey(story.ownerId),
    story.ownerId === viewerId ? getStoryViews(story.storyId) : Promise.resolve([]),
    story.ownerId === viewerId ? getStoryShares(story.storyId) : Promise.resolve(0)
  ]);
  const feedback = story.ownerId === viewerId
    ? allFeedback
    : allFeedback.filter((record) => record.viewerId === viewerId || (record.kind === "comment" && record.encryptionMode === "story"));
  return {
    storyId: story.storyId,
    ownerId: story.ownerId,
    contentKind: ["reel", "highlight"].includes(story.contentKind) ? story.contentKind : "story",
    createdAt: story.createdAt,
    expiresAt: story.expiresAt,
    profile: story.profile,
    publicKeyJwk: ownerPublicKey,
    encryptedContent: story.encryptedContent,
    encryptedKey,
    viewers,
    feedback: await Promise.all(feedback.map((record) => storyFeedbackEnvelope(record, story))),
    shareCount
  };
}

async function addStoryView(storyId, viewerId, profile = {}, story = {}, details = {}) {
  const ttl = contentRecordTtlSeconds(story);
  if (!memoryStoryViews.has(storyId) || !(memoryStoryViews.get(storyId) instanceof Map)) memoryStoryViews.set(storyId, new Map());
  const existing = memoryStoryViews.get(storyId).get(viewerId);
  const record = existing
    ? { ...existing, ...details, profile: Object.keys(profile || {}).length ? profile : existing.profile || {} }
    : { viewerId, viewedAt: new Date().toISOString(), profile, ...details };
  memoryStoryViews.get(storyId).set(viewerId, record);
  if (redis) {
    await redis.hset(storyViewDetailsKey(storyId), viewerId, JSON.stringify(record));
    await redis.expire(storyViewDetailsKey(storyId), ttl + 300);
  }
  if (upstashRestEnabled) await upstashPipeline([
    ["HSET", storyViewDetailsKey(storyId), viewerId, JSON.stringify(record)],
    ["EXPIRE", storyViewDetailsKey(storyId), ttl + 300]
  ]);
  return record;
}

async function getStoryViews(storyId) {
  let values = [];
  if (redis) values = Object.values(await redis.hgetall(storyViewDetailsKey(storyId)) || {});
  if (upstashRestEnabled) {
    const raw = await upstashCommand(["HGETALL", storyViewDetailsKey(storyId)]) || [];
    values = Array.isArray(raw) ? raw.filter((_, index) => index % 2 === 1) : Object.values(raw);
  }
  if (!redis && !upstashRestEnabled) return [...(memoryStoryViews.get(storyId)?.values?.() || [])];
  return values.map(safeJsonParse).filter((record) => record?.viewerId && record?.viewedAt);
}

async function setStoryReaction(record, story = {}) {
  const ttl = contentRecordTtlSeconds(story);
  if (!memoryStoryReactions.has(record.storyId)) memoryStoryReactions.set(record.storyId, new Map());
  if (record.reaction === "none") memoryStoryReactions.get(record.storyId).delete(record.viewerId);
  else memoryStoryReactions.get(record.storyId).set(record.viewerId, record);
  if (redis) {
    if (record.reaction === "none") await redis.hdel(storyReactionsKey(record.storyId), record.viewerId);
    else await redis.hset(storyReactionsKey(record.storyId), record.viewerId, JSON.stringify(record));
    await redis.expire(storyReactionsKey(record.storyId), ttl + 300);
  }
  if (upstashRestEnabled) await upstashPipeline([
    record.reaction === "none"
      ? ["HDEL", storyReactionsKey(record.storyId), record.viewerId]
      : ["HSET", storyReactionsKey(record.storyId), record.viewerId, JSON.stringify(record)],
    ["EXPIRE", storyReactionsKey(record.storyId), ttl + 300]
  ]);
}

async function appendStoryComment(record, story = {}) {
  const ttl = contentRecordTtlSeconds(story);
  if (!memoryStoryComments.has(record.storyId)) memoryStoryComments.set(record.storyId, []);
  const comments = memoryStoryComments.get(record.storyId);
  comments.push(record);
  if (comments.length > 200) comments.splice(0, comments.length - 200);
  if (redis) {
    await redis.rpush(storyCommentsKey(record.storyId), JSON.stringify(record));
    await redis.ltrim(storyCommentsKey(record.storyId), -200, -1);
    await redis.expire(storyCommentsKey(record.storyId), ttl + 300);
  }
  if (upstashRestEnabled) await upstashPipeline([
    ["RPUSH", storyCommentsKey(record.storyId), JSON.stringify(record)],
    ["LTRIM", storyCommentsKey(record.storyId), -200, -1],
    ["EXPIRE", storyCommentsKey(record.storyId), ttl + 300]
  ]);
}

async function getStoryFeedback(storyId) {
  let reactions = [];
  let comments = [];
  if (!redis && !upstashRestEnabled) {
    reactions = [...(memoryStoryReactions.get(storyId)?.values?.() || [])];
    comments = [...(memoryStoryComments.get(storyId) || [])];
  }
  if (redis) {
    reactions = Object.values(await redis.hgetall(storyReactionsKey(storyId)) || {}).map(safeJsonParse).filter(Boolean);
    comments = (await redis.lrange(storyCommentsKey(storyId), 0, -1)).map(safeJsonParse).filter(Boolean);
  }
  if (upstashRestEnabled) {
    const rawReactions = await upstashCommand(["HGETALL", storyReactionsKey(storyId)]) || [];
    const reactionValues = Array.isArray(rawReactions) ? rawReactions.filter((_, index) => index % 2 === 1) : Object.values(rawReactions);
    reactions = reactionValues.map(safeJsonParse).filter(Boolean);
    comments = (await upstashCommand(["LRANGE", storyCommentsKey(storyId), 0, -1]) || []).map(safeJsonParse).filter(Boolean);
  }
  return [...reactions, ...comments].sort((left, right) => Date.parse(left.createdAt) - Date.parse(right.createdAt));
}

async function storyFeedbackEnvelope(record, story) {
  return {
    ...record,
    ownerPublicKeyJwk: await getPublicKey(story.ownerId),
    viewerPublicKeyJwk: record.viewerPublicKeyJwk || await getPublicKey(record.viewerId)
  };
}

async function addStoryShares(storyId, count, story = {}) {
  const ttl = contentRecordTtlSeconds(story);
  const next = Number(memoryStoryShares.get(storyId) || 0) + count;
  memoryStoryShares.set(storyId, next);
  if (redis) {
    const result = Number(await redis.incrby(storySharesKey(storyId), count));
    await redis.expire(storySharesKey(storyId), ttl + 300);
    return result;
  }
  if (upstashRestEnabled) {
    const [increment] = await upstashPipeline([
      ["INCRBY", storySharesKey(storyId), count],
      ["EXPIRE", storySharesKey(storyId), ttl + 300]
    ]);
    return Number(increment || next);
  }
  return next;
}

async function getStoryShares(storyId) {
  if (redis) return Number(await redis.get(storySharesKey(storyId)) || 0);
  if (upstashRestEnabled) return Number(await upstashCommand(["GET", storySharesKey(storyId)]) || 0);
  return Number(memoryStoryShares.get(storyId) || 0);
}

async function removeStoryRecord(story) {
  memoryStories.delete(story.storyId);
  memoryStoryViews.delete(story.storyId);
  memoryStoryReactions.delete(story.storyId);
  memoryStoryComments.delete(story.storyId);
  memoryStoryShares.delete(story.storyId);
  const viewerIds = Object.keys(story.encryptedKeys || {});
  for (const viewerId of viewerIds) memoryStoryIndexes.get(viewerId)?.delete(story.storyId);
  if (redis) {
    const pipeline = redis.multi();
    pipeline.del(storyKey(story.storyId), storyViewsKey(story.storyId), storyViewDetailsKey(story.storyId), storyReactionsKey(story.storyId), storyCommentsKey(story.storyId), storySharesKey(story.storyId));
    for (const viewerId of viewerIds) pipeline.zrem(storyIndexKey(viewerId), story.storyId);
    pipeline.zrem(storyOwnerIndexKey(story.ownerId), story.storyId);
    await pipeline.exec();
  }
  if (upstashRestEnabled) {
    const commands = [["DEL", storyKey(story.storyId), storyViewsKey(story.storyId), storyViewDetailsKey(story.storyId), storyReactionsKey(story.storyId), storyCommentsKey(story.storyId), storySharesKey(story.storyId)]];
    for (const viewerId of viewerIds) commands.push(["ZREM", storyIndexKey(viewerId), story.storyId]);
    commands.push(["ZREM", storyOwnerIndexKey(story.ownerId), story.storyId]);
    await upstashPipeline(commands);
  }
}

async function deleteStoriesOwnedBy(peerId) {
  let ids = [...memoryStories.values()]
    .filter((story) => story.ownerId === peerId)
    .map((story) => story.storyId);
  if (redis) ids = await redis.zrange(storyOwnerIndexKey(peerId), 0, -1);
  if (upstashRestEnabled) ids = await upstashCommand(["ZRANGE", storyOwnerIndexKey(peerId), 0, -1]) || [];
  for (const storyId of new Set(ids)) {
    const story = await getStoryRecord(storyId);
    if (story) await removeStoryRecord(story);
  }
  if (redis) await redis.del(storyOwnerIndexKey(peerId));
  if (upstashRestEnabled) await upstashCommand(["DEL", storyOwnerIndexKey(peerId)]);
}

async function deleteSocialDrafts(peerId) {
  memorySocialDrafts.delete(peerId);
  const keys = [socialDraftKey(peerId, "story"), socialDraftKey(peerId, "reel")];
  if (redis) await redis.del(...keys);
  if (upstashRestEnabled) await upstashCommand(["DEL", ...keys]);
}

async function deleteAccountData(peerId) {
  await Promise.all([
    removeAccount(peerId),
    removePublicKey(peerId),
    removeProfile(peerId),
    removeQuickAddProfile(peerId),
    removeSyncedContacts(peerId),
    deleteAllQueuedMessages(peerId),
    deleteAllHistoryMessages(peerId),
    deleteStoriesOwnedBy(peerId),
    deleteSocialDrafts(peerId),
    removeAccountIndex(peerId),
    removeWalletForDeletedAccount(peerId)
  ]);
}

async function removeWalletForDeletedAccount(peerId) {
  memoryWallets.delete(peerId);
  memoryWalletIndexes.delete(peerId);
  if (redis) await redis.del(walletKey(peerId), walletTransactionIndexKey(peerId));
  if (upstashRestEnabled) await upstashCommand(["DEL", walletKey(peerId), walletTransactionIndexKey(peerId)]);
}

async function deleteAccountBySupport(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean) return { peerId: "", existed: false, cleaned: false };
  const existed = await accountHasAdminFootprint(clean, { includeLiveClient: true });
  await removePeerFromGroups(clean);
  await deleteAccountData(clean);
  await revokePeerSessions(clean);
  await removeAccountRestriction(clean);
  await consumeOwnerResetCode(clean);
  disconnectPeer(clean, "This account was deleted by support.");
  const remaining = await accountHasAdminFootprint(clean);
  return { peerId: clean, existed, cleaned: !remaining };
}

async function accountHasAdminFootprint(peerId, { includeLiveClient = false } = {}) {
  const clean = cleanPeerId(peerId);
  if (!clean) return false;
  const [account, profile, publicKey, restriction, ownerReset] = await Promise.all([
    getAccount(clean),
    getProfile(clean),
    getPublicKey(clean),
    getAccountRestriction(clean),
    getOwnerResetRecord(clean)
  ]);
  return Boolean(
    account
    || profileHasAccountFootprint(profile)
    || publicKey
    || restrictionHasAnyFlag(restriction)
    || ownerReset
    || (includeLiveClient && clients.has(clean))
  );
}

async function removePeerFromGroups(peerId) {
  const groups = await getGroupsForMember(peerId);
  for (const group of groups) {
    const remainingMembers = group.members.filter((id) => id !== peerId);
    if (!remainingMembers.length) {
      await deleteGroup(group.id);
      broadcastGroupUpdate({ ...group, members: [] }, [peerId]);
      continue;
    }
    group.members = remainingMembers;
    group.admins = (group.admins || []).filter((id) => id !== peerId && remainingMembers.includes(id));
    if (group.ownerId === peerId) {
      group.ownerId = group.admins[0] || remainingMembers[0];
      group.admins = normalizeMembers([group.ownerId, ...group.admins]).filter((id) => remainingMembers.includes(id));
    }
    group.updatedAt = new Date().toISOString();
    await setGroup(group);
    broadcastGroupUpdate(group, [peerId]);
  }
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
  await updateAccountIndex(peerId, profile);
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

async function updateAccountIndex(peerId, profile = null, account = null) {
  const clean = cleanPeerId(peerId);
  if (!clean) return;
  const indexedAccount = account || await getAccount(clean);
  const indexedProfile = sanitizeProfile(profile || indexedAccount?.profile || await getProfile(clean) || {});
  const summary = {
    peerId: clean,
    displayName: indexedProfile.displayName || "Bypassium User",
    profilePicture: indexedProfile.profilePicture || "",
    badge: indexedProfile.badge || "",
    joinedAt: indexedProfile.joinedAt || indexedAccount?.createdAt || "",
    updatedAt: indexedProfile.updatedAt || indexedAccount?.updatedAt || "",
    quickAddVisible: indexedProfile.quickAddVisible !== false
  };
  memoryAccountIndex.add(clean);
  memoryAccountSearch.set(clean, summary);
  if (redis) {
    await redis.sadd(accountIndexKey(), clean);
    await redis.hset(accountSearchIndexKey(), clean, JSON.stringify(summary));
  }
  if (upstashRestEnabled) {
    await upstashPipeline([
      ["SADD", accountIndexKey(), clean],
      ["HSET", accountSearchIndexKey(), clean, JSON.stringify(summary)]
    ]);
  }
}

async function removeAccountIndex(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean) return;
  memoryAccountIndex.delete(clean);
  memoryAccountSearch.delete(clean);
  if (redis) {
    await redis.srem(accountIndexKey(), clean);
    await redis.hdel(accountSearchIndexKey(), clean);
  }
  if (upstashRestEnabled) {
    await upstashPipeline([
      ["SREM", accountIndexKey(), clean],
      ["HDEL", accountSearchIndexKey(), clean]
    ]);
  }
}

async function getIndexedPeerIds() {
  const ids = new Set(memoryAccountIndex);
  if (redis) {
    for (const id of await redis.smembers(accountIndexKey())) ids.add(id);
  }
  if (upstashRestEnabled) {
    for (const id of await upstashCommand(["SMEMBERS", accountIndexKey()]) || []) ids.add(id);
  }
  return [...ids].filter(cleanPeerId);
}

async function getAccountSearchEntries() {
  const entries = new Map(memoryAccountSearch);
  if (redis) {
    const stored = await redis.hgetall(accountSearchIndexKey());
    for (const [id, value] of Object.entries(stored || {})) {
      const parsed = parseAccountSearchEntry(value);
      if (parsed) entries.set(id, parsed);
    }
  }
  if (upstashRestEnabled) {
    const stored = await upstashCommand(["HGETALL", accountSearchIndexKey()]) || [];
    if (Array.isArray(stored)) {
      for (let index = 0; index < stored.length; index += 2) {
        const parsed = parseAccountSearchEntry(stored[index + 1]);
        if (parsed) entries.set(stored[index], parsed);
      }
    } else if (stored && typeof stored === "object") {
      for (const [id, value] of Object.entries(stored)) {
        const parsed = parseAccountSearchEntry(value);
        if (parsed) entries.set(id, parsed);
      }
    }
  }
  return [...entries.entries()]
    .map(([id, profile]) => ({ id, profile: sanitizeProfile(profile) }))
    .filter(({ id }) => cleanPeerId(id));
}

function parseAccountSearchEntry(value) {
  try {
    return value ? sanitizeProfile(typeof value === "string" ? JSON.parse(value) : value) : null;
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

async function searchAdminAccounts(query = "", limit = 80) {
  const cleanQuery = String(query || "").trim().toLowerCase();
  const directoryProfiles = await getQuickAddProfileMap();
  const ids = new Set([...(await getKnownPeerIds()), ...directoryProfiles.keys()]);
  if (/^\d{6}$/.test(cleanQuery)) ids.add(cleanQuery);
  const summaries = await adminAccountSummaries([...ids], directoryProfiles);
  const accounts = [];
  for (const account of summaries) {
    const score = cleanQuery ? accountSearchScore(cleanQuery, account.peerId, account.displayName) : 0;
    if (score === null) continue;
    accounts.push({ ...account, score });
  }
  return accounts.sort((first, second) => {
    if (first.score !== second.score) return first.score - second.score;
    if (first.banned !== second.banned) return first.banned ? -1 : 1;
    if (first.status !== second.status) return first.status === "online" ? -1 : 1;
    return first.displayName.localeCompare(second.displayName);
  }).slice(0, limit).map(({ score, ...account }) => account);
}

async function getQuickAddProfileMap() {
  try {
    return new Map((await getQuickAddDirectoryEntries()).map(({ id, profile }) => [id, profile]));
  } catch {
    return new Map();
  }
}

async function adminAccountSummaries(peerIds, fallbackProfiles = new Map()) {
  const cleanIds = [...new Set(peerIds.map(cleanPeerId).filter(Boolean))];
  if (!cleanIds.length) return [];
  if (upstashRestEnabled) return adminAccountSummariesFromUpstash(cleanIds, fallbackProfiles);
  if (redis) return adminAccountSummariesFromRedis(cleanIds, fallbackProfiles);
  return (await Promise.all(cleanIds.map((id) => adminAccountSummary(id, fallbackProfiles.get(id))))).filter(Boolean);
}

async function adminAccountSummariesFromUpstash(peerIds, fallbackProfiles) {
  const summaries = [];
  for (let index = 0; index < peerIds.length; index += 30) {
    const chunk = peerIds.slice(index, index + 30);
    const commands = [];
    for (const id of chunk) {
      commands.push(["GET", accountKey(id)], ["GET", profileKey(id)], ["GET", restrictionKey(id)]);
    }
    const results = await upstashPipeline(commands);
    for (let offset = 0; offset < chunk.length; offset += 1) {
      const id = chunk[offset];
      const base = offset * 3;
      const summary = adminAccountSummaryFromValues(
        id,
        parseStoredAccount(results[base]),
        parseStoredProfile(results[base + 1]) || fallbackProfiles.get(id) || null,
        parseStoredRestriction(results[base + 2])
      );
      if (summary) summaries.push(summary);
    }
  }
  return summaries;
}

async function adminAccountSummariesFromRedis(peerIds, fallbackProfiles) {
  const accountValues = await redis.mget(...peerIds.map(accountKey));
  const profileValues = await redis.mget(...peerIds.map(profileKey));
  const restrictionValues = await redis.mget(...peerIds.map(restrictionKey));
  return peerIds
    .map((id, index) => adminAccountSummaryFromValues(
      id,
      parseStoredAccount(accountValues[index]),
      parseStoredProfile(profileValues[index]) || fallbackProfiles.get(id) || null,
      parseStoredRestriction(restrictionValues[index])
    ))
    .filter(Boolean);
}

async function adminAccountSummary(peerId, fallbackProfile = null) {
  const account = await getAccount(peerId);
  const profile = sanitizeProfile(account?.profile || await getProfile(peerId) || fallbackProfile || {});
  const restriction = await getAccountRestriction(peerId);
  return adminAccountSummaryFromValues(peerId, account, profile, restriction);
}

function adminAccountSummaryFromValues(peerId, account = null, profileValue = null, restrictionValue = {}) {
  const profile = sanitizeProfile(account?.profile || profileValue || {});
  const restriction = normalizeRestriction(restrictionValue || {});
  if (!account && !profileHasAccountFootprint(profileValue) && !restrictionHasAnyFlag(restriction)) return null;
  const banned = restrictionBanned(restriction);
  return {
    peerId,
    displayName: profile.displayName || "Bypassium User",
    profilePicture: profile.profilePicture || "",
    badge: profile.badge || "",
    status: clients.has(peerId) ? "online" : "offline",
    hasPassword: Boolean(account?.passwordHash),
    hasRecoveryPhrase: Boolean(account?.recoveryHash),
    quickAddVisible: profile.quickAddVisible !== false,
    banned,
    banReason: restriction.banReason || "",
    bannedUntil: restriction.bannedUntil || "",
    sendDisabled: Boolean(restriction.sendDisabled),
    groupsDisabled: Boolean(restriction.groupsDisabled),
    quickAddHidden: Boolean(restriction.quickAddHidden),
    passwordResetRequired: Boolean(restriction.passwordResetRequired),
    createdAt: account?.createdAt || profile.joinedAt || "",
    updatedAt: account?.updatedAt || profile.updatedAt || ""
  };
}

function profileHasAccountFootprint(profile = null) {
  if (!profile || typeof profile !== "object") return false;
  const clean = sanitizeProfile(profile);
  return Boolean(clean.displayName || clean.profilePicture || clean.badge || clean.joinedAt || clean.updatedAt);
}

function parseStoredAccount(value) {
  try {
    return value ? sanitizeAccount(typeof value === "string" ? JSON.parse(value) : value) : null;
  } catch {
    return null;
  }
}

function parseStoredRestriction(value) {
  try {
    return value ? normalizeRestriction(typeof value === "string" ? JSON.parse(value) : value) : {};
  } catch {
    return {};
  }
}

async function adminAccountDetail(peerId) {
  const account = await getAccount(peerId);
  const profile = await getProfile(peerId);
  const publicKey = await getPublicKey(peerId);
  if (!account && !profile && !publicKey) return null;
  return {
    ...(await adminAccountSummary(peerId)),
    wallet: await walletSummary(peerId, 40),
    queuedMessages: await countQueuedMessages(peerId),
    sessionCount: await countPeerSessions(peerId),
    groupCount: (await getGroupsForMember(peerId)).length,
    hasPublicKey: Boolean(publicKey),
    storage: storageMode()
  };
}

async function searchAdminGroups(query = "", limit = 80) {
  const cleanQuery = String(query || "").trim().toLowerCase();
  const summaries = [];
  for (const group of await getAllGroups()) {
    const summary = await adminGroupSummary(group);
    const score = groupSearchScore(cleanQuery, summary);
    if (score === null) continue;
    summaries.push({ ...summary, score });
  }
  return summaries.sort((first, second) => {
    if (first.score !== second.score) return first.score - second.score;
    const firstTime = Date.parse(first.updatedAt || "") || 0;
    const secondTime = Date.parse(second.updatedAt || "") || 0;
    if (firstTime !== secondTime) return secondTime - firstTime;
    return first.name.localeCompare(second.name);
  }).slice(0, limit).map(({ score, ...group }) => group);
}

async function adminGroupDetail(groupId) {
  const group = await getGroup(groupId);
  if (!group) return null;
  return adminGroupSummary(group);
}

async function adminGroupSummary(groupValue) {
  const group = normalizeGroup(groupValue);
  const members = await Promise.all(group.members.map((memberId) => adminMemberSummary(memberId)));
  const owner = members.find((member) => member.peerId === group.ownerId) || null;
  return {
    groupId: group.id,
    name: sanitizeGroupName(group.name, "Group chat"),
    avatar: sanitizeProfilePicture(group.avatar),
    createdBy: cleanPeerId(group.createdBy),
    ownerId: group.ownerId,
    ownerName: owner?.displayName || group.ownerId || "unknown",
    admins: normalizeMembers(group.admins || []),
    adminCount: normalizeMembers(group.admins || []).length,
    members,
    memberCount: members.length,
    memberAddLocked: Boolean(group.memberAddLocked),
    createdAt: String(group.createdAt || "").slice(0, 40),
    updatedAt: String(group.updatedAt || "").slice(0, 40)
  };
}

async function adminMemberSummary(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean) return { peerId: "", displayName: "Unknown", profilePicture: "", badge: "", status: "offline", banned: false };
  const accountSummary = await adminAccountSummary(clean).catch(() => null);
  if (accountSummary) {
    return {
      peerId: clean,
      displayName: accountSummary.displayName || clean,
      profilePicture: accountSummary.profilePicture || "",
      badge: accountSummary.badge || "",
      status: accountSummary.status || "offline",
      banned: Boolean(accountSummary.banned)
    };
  }
  const profile = sanitizeProfile(await getProfile(clean) || {});
  const restriction = await getAccountRestriction(clean);
  return {
    peerId: clean,
    displayName: profile.displayName || clean,
    profilePicture: profile.profilePicture || "",
    badge: profile.badge || "",
    status: clients.has(clean) ? "online" : "offline",
    banned: restrictionBanned(restriction)
  };
}

function groupSearchScore(query, group) {
  if (!query) return 0;
  const scores = [
    accountSearchScore(query, group.groupId, group.name),
    accountSearchScore(query, group.ownerId, group.ownerName),
    ...group.members.map((member) => accountSearchScore(query, member.peerId, member.displayName))
  ].filter((score) => Number.isFinite(score));
  return scores.length ? Math.min(...scores) : null;
}

function cleanAdminGroupId(value) {
  const groupId = String(value || "").trim();
  return groupId && groupId.length <= 120 && /^[A-Za-z0-9_-]+$/.test(groupId) ? groupId : "";
}

function sanitizeGroupName(value = "", fallback = "Group chat") {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80)
    || fallback;
}

async function getKnownPeerIds() {
  const indexedIds = await getIndexedPeerIds();
  if (indexedIds.length && accountIndexHydrated) return indexedIds;
  const ids = new Set([
    ...indexedIds,
    ...memoryAccounts.keys(),
    ...memoryAccountIndex,
    ...memoryProfiles.keys(),
    ...memoryPublicKeys.keys(),
    ...memoryDirectory.keys(),
    ...memoryRestrictions.keys()
  ]);
  if (!accountIndexHydrated) scheduleAccountIndexHydration();
  return [...ids].filter((id) => /^\d{6}$/.test(id));
}

function scheduleAccountIndexHydration() {
  if (accountIndexHydrated || accountIndexHydrationPromise) return;
  accountIndexHydrationPromise = hydrateAccountIndex()
    .catch((error) => console.error("Account index hydration failed:", error.message))
    .finally(() => {
      accountIndexHydrationPromise = null;
    });
}

async function hydrateAccountIndex() {
  const ids = new Set(await getIndexedPeerIds());
  if (redis || upstashRestEnabled) {
    for (const [pattern, prefix] of [
      ["bypassium:account:*", "bypassium:account:"],
      ["bypassium:profile:*", "bypassium:profile:"],
      ["bypassium:public-key:*", "bypassium:public-key:"],
      ["bypassium:restriction:*", "bypassium:restriction:"]
    ]) {
      const keys = await listKeys(pattern);
      for (const key of keys) {
        const id = String(key || "").slice(prefix.length);
        if (/^\d{6}$/.test(id)) ids.add(id);
      }
    }
  }
  for (const id of ids) {
    await updateAccountIndex(id).catch((error) => {
      console.error("Account index hydrate failed:", error.message);
    });
  }
  accountIndexHydrated = true;
}

async function countQueuedMessages(peerId) {
  const memoryCount = (memoryOfflineMessages.get(peerId) || []).length;
  const ids = await getInboxIds(peerId);
  return Math.max(memoryCount, new Set(ids || []).size);
}

async function countPeerSessions(peerId) {
  let count = 0;
  for (const session of sessions.values()) {
    if (session.peerId === peerId && session.expiresAt > Date.now()) count += 1;
  }
  let persisted = [];
  if (redis) persisted = await redis.smembers(sessionIndexKey(peerId));
  if (upstashRestEnabled) persisted = await upstashCommand(["SMEMBERS", sessionIndexKey(peerId)]) || [];
  return Math.max(count, new Set(persisted).size);
}

async function getAccountRestriction(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean) return {};
  if (memoryRestrictions.has(clean)) return normalizeRestriction(memoryRestrictions.get(clean));
  let stored = null;
  if (redis) stored = await redis.get(restrictionKey(clean));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", restrictionKey(clean)]);
  // Cache the unrestricted case too. Without this negative cache, every normal
  // message paid for a remote Redis/Upstash GET before it could be accepted.
  if (!stored) {
    memoryRestrictions.set(clean, {});
    return {};
  }
  const restriction = normalizeRestriction(JSON.parse(stored));
  memoryRestrictions.set(clean, restriction);
  return restriction;
}

async function setAccountRestriction(peerId, patch = {}) {
  const clean = cleanPeerId(peerId);
  if (!clean) return {};
  const current = await getAccountRestriction(clean);
  const next = normalizeRestriction({ ...current, ...patch, updatedAt: new Date().toISOString() });
  if (!restrictionHasAnyFlag(next)) {
    await removeAccountRestriction(clean);
    return {};
  }
  memoryRestrictions.set(clean, next);
  if (redis) await redis.set(restrictionKey(clean), JSON.stringify(next));
  if (upstashRestEnabled) await upstashCommand(["SET", restrictionKey(clean), JSON.stringify(next)]);
  return next;
}

async function removeAccountRestriction(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean) return;
  memoryRestrictions.delete(clean);
  if (redis) await redis.del(restrictionKey(clean));
  if (upstashRestEnabled) await upstashCommand(["DEL", restrictionKey(clean)]);
}

function normalizeRestriction(value = {}) {
  return {
    banned: Boolean(value.banned),
    banReason: String(value.banReason || "").slice(0, 240),
    bannedAt: String(value.bannedAt || "").slice(0, 40),
    bannedUntil: normalizeAdminDate(value.bannedUntil),
    sendDisabled: Boolean(value.sendDisabled),
    groupsDisabled: Boolean(value.groupsDisabled),
    quickAddHidden: Boolean(value.quickAddHidden),
    passwordResetRequired: Boolean(value.passwordResetRequired),
    resetRequestedAt: String(value.resetRequestedAt || "").slice(0, 40),
    updatedAt: String(value.updatedAt || "").slice(0, 40)
  };
}

function restrictionHasAnyFlag(restriction = {}) {
  return Boolean(
    restrictionBanned(restriction)
    || restriction.sendDisabled
    || restriction.groupsDisabled
    || restriction.quickAddHidden
    || restriction.passwordResetRequired
  );
}

function restrictionBanned(restriction = {}) {
  if (!restriction.banned) return false;
  if (!restriction.bannedUntil) return true;
  const until = Date.parse(restriction.bannedUntil);
  return Number.isFinite(until) && until > Date.now();
}

async function accountBlockMessage(peerId, action = "account", { allowForcedReset = false } = {}) {
  const info = await accountBlockInfo(peerId, action, { allowForcedReset });
  return info?.message || "";
}

async function accountBlockInfo(peerId, action = "account", { allowForcedReset = false } = {}) {
  const clean = cleanPeerId(peerId);
  const restriction = await getAccountRestriction(peerId);
  if (restrictionBanned(restriction)) return accountBanPayload(clean, restriction);
  if (restriction.passwordResetRequired && !allowForcedReset) {
    return {
      code: "password-reset-required",
      peerId: clean,
      message: "This account must reset its password before continuing."
    };
  }
  if (action === "send" && restriction.sendDisabled) {
    return {
      code: "send-disabled",
      peerId: clean,
      message: "Support has disabled message sending for this account."
    };
  }
  if (action === "groups" && restriction.groupsDisabled) {
    return {
      code: "groups-disabled",
      peerId: clean,
      message: "Support has disabled group actions for this account."
    };
  }
  if (action === "quick-add" && restriction.quickAddHidden) {
    return {
      code: "quick-add-hidden",
      peerId: clean,
      message: "Support has hidden this account from public discovery."
    };
  }
  return null;
}

function accountBanMessage(restriction = {}) {
  return restriction.banReason ? `Account banned: ${restriction.banReason}` : "This account is banned.";
}

function accountBanPayload(peerId, restriction = {}) {
  return {
    code: "account-banned",
    peerId: cleanPeerId(peerId),
    banned: true,
    banReason: restriction.banReason || "",
    bannedUntil: restriction.bannedUntil || "",
    message: accountBanMessage(restriction)
  };
}

async function enforceAccountAction(socket, peerId, action) {
  const block = await accountBlockInfo(peerId, action);
  if (!block) return true;
  send(socket, {
    type: block.code === "account-banned" ? "account-banned" : "error",
    ...block
  });
  return false;
}

async function accountQuickAddHidden(peerId) {
  const restriction = await getAccountRestriction(peerId);
  return restrictionBanned(restriction) || restriction.quickAddHidden;
}

async function accountGroupsDisabled(peerId) {
  const restriction = await getAccountRestriction(peerId);
  return restrictionBanned(restriction) || restriction.groupsDisabled;
}

async function createOwnerResetCode(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean || !(await getAccount(clean))) throw new Error("Account not found.");
  const code = `BYP-${randomBytes(4).toString("hex").toUpperCase()}`;
  const salt = randomBytes(12).toString("base64url");
  const expiresAt = new Date(Date.now() + ADMIN_RESET_TTL_SECONDS * 1000).toISOString();
  const record = {
    peerId: clean,
    salt,
    codeHash: hashOwnerResetCode(clean, code, salt),
    expiresAt,
    createdAt: new Date().toISOString()
  };
  memoryOwnerResetCodes.set(clean, record);
  if (redis) await redis.set(ownerResetKey(clean), JSON.stringify(record), "EX", ADMIN_RESET_TTL_SECONDS);
  if (upstashRestEnabled) await upstashCommand(["SET", ownerResetKey(clean), JSON.stringify(record), "EX", ADMIN_RESET_TTL_SECONDS]);
  return { code, expiresAt };
}

async function verifyOwnerResetCode(peerId, code) {
  const clean = cleanPeerId(peerId);
  const record = await getOwnerResetRecord(clean);
  if (!record || Date.parse(record.expiresAt) < Date.now()) return false;
  const actual = hashOwnerResetCode(clean, normalizeOwnerResetCode(code), record.salt);
  return safeEqualString(actual, record.codeHash);
}

async function findPeerIdForOwnerResetCode(code) {
  const cleanCode = normalizeOwnerResetCode(code);
  if (!validOwnerResetCode(cleanCode)) return "";
  const ids = new Set(memoryOwnerResetCodes.keys());
  if (redis || upstashRestEnabled) {
    const keys = await listKeys("bypassium:owner-reset:*");
    for (const key of keys) {
      const id = String(key || "").slice("bypassium:owner-reset:".length);
      if (cleanPeerId(id)) ids.add(id);
    }
  }
  for (const peerId of ids) {
    if (await verifyOwnerResetCode(peerId, cleanCode)) return peerId;
  }
  return "";
}

async function getOwnerResetRecord(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean) return null;
  if (memoryOwnerResetCodes.has(clean)) return memoryOwnerResetCodes.get(clean);
  let stored = null;
  if (redis) stored = await redis.get(ownerResetKey(clean));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", ownerResetKey(clean)]);
  if (!stored) return null;
  const record = JSON.parse(stored);
  memoryOwnerResetCodes.set(clean, record);
  return record;
}

async function consumeOwnerResetCode(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean) return;
  memoryOwnerResetCodes.delete(clean);
  if (redis) await redis.del(ownerResetKey(clean));
  if (upstashRestEnabled) await upstashCommand(["DEL", ownerResetKey(clean)]);
}

function hashOwnerResetCode(peerId, code, salt) {
  return scryptSync(`owner-reset:${peerId}:${normalizeOwnerResetCode(code)}`, salt, 32).toString("base64url");
}

async function recordAdminAudit(action, peerId = "", details = {}) {
  const entry = {
    id: randomUUID(),
    at: new Date().toISOString(),
    action: String(action || "").slice(0, 80),
    peerId: cleanPeerId(peerId),
    details
  };
  memoryAdminAudit.unshift(entry);
  memoryAdminAudit.splice(ADMIN_AUDIT_LIMIT);
  if (redis) {
    await redis.lpush(adminAuditKey(), JSON.stringify(entry));
    await redis.ltrim(adminAuditKey(), 0, ADMIN_AUDIT_LIMIT - 1);
  }
  if (upstashRestEnabled) {
    await upstashPipeline([
      ["LPUSH", adminAuditKey(), JSON.stringify(entry)],
      ["LTRIM", adminAuditKey(), 0, ADMIN_AUDIT_LIMIT - 1]
    ]);
  }
  void recordSafetyLog(`admin:${entry.action}`, peerId, details).catch((error) => console.error("Safety log write failed:", error.message));
  return entry;
}

async function getAdminAudit() {
  if (redis) return (await redis.lrange(adminAuditKey(), 0, ADMIN_AUDIT_LIMIT - 1)).map(parseAuditEntry).filter(Boolean);
  if (upstashRestEnabled) return (await upstashCommand(["LRANGE", adminAuditKey(), 0, ADMIN_AUDIT_LIMIT - 1]) || []).map(parseAuditEntry).filter(Boolean);
  return memoryAdminAudit;
}

function parseAuditEntry(value) {
  try {
    return typeof value === "string" ? JSON.parse(value) : value;
  } catch {
    return null;
  }
}

async function recordSafetyLog(action, peerId = "", details = {}) {
  const entry = {
    id: randomUUID(),
    at: new Date().toISOString(),
    action: String(action || "").slice(0, 80),
    peerId: cleanPeerId(peerId),
    details: sanitizeSafetyDetails(details)
  };
  memorySafetyLog.unshift(entry);
  memorySafetyLog.splice(SAFETY_LOG_LIMIT);
  if (redis) {
    await redis.lpush(safetyLogKey(), JSON.stringify(entry));
    await redis.ltrim(safetyLogKey(), 0, SAFETY_LOG_LIMIT - 1);
  }
  if (upstashRestEnabled) {
    await upstashPipeline([
      ["LPUSH", safetyLogKey(), JSON.stringify(entry)],
      ["LTRIM", safetyLogKey(), 0, SAFETY_LOG_LIMIT - 1]
    ]);
  }
  return entry;
}

async function getSafetyLog() {
  if (redis) return (await redis.lrange(safetyLogKey(), 0, SAFETY_LOG_LIMIT - 1)).map(parseAuditEntry).filter(Boolean);
  if (upstashRestEnabled) return (await upstashCommand(["LRANGE", safetyLogKey(), 0, SAFETY_LOG_LIMIT - 1]) || []).map(parseAuditEntry).filter(Boolean);
  return memorySafetyLog;
}

function sanitizeSafetyDetails(details = {}) {
  const json = JSON.stringify(details || {});
  if (json.length <= 1200) return details || {};
  return { truncated: true, preview: json.slice(0, 1200) };
}

function disconnectPeer(peerId, message, payload = null) {
  const sockets = clients.get(peerId);
  if (!sockets) return;
  for (const socket of sockets) {
    if (payload) send(socket, { type: payload.type || "account-banned", message, ...payload });
    else send(socket, { type: "error", message });
    socket.close(4003, message.slice(0, 120));
  }
}

function cleanPeerId(value) {
  const peerId = String(value || "").trim();
  return /^\d{6}$/.test(peerId) ? peerId : "";
}

function sanitizeSyncedContacts(contacts = [], ownerId = "") {
  if (!Array.isArray(contacts)) return [];
  const cleanOwnerId = cleanPeerId(ownerId);
  const seen = new Set();
  const clean = [];
  for (const contact of contacts.slice(0, 1000)) {
    const normalized = sanitizeSyncedContact(contact);
    if (!normalized || normalized.id === cleanOwnerId || seen.has(normalized.id)) continue;
    seen.add(normalized.id);
    clean.push(normalized);
  }
  return clean;
}

function sanitizeSyncedContact(contact = {}) {
  const id = cleanPeerId(contact.id);
  if (!id) return null;
  return {
    id,
    name: String(contact.name || id).trim().slice(0, 80) || id,
    remoteDisplayName: String(contact.remoteDisplayName || "").trim().slice(0, 80),
    remoteBadge: sanitizeProfileBadge(contact.remoteBadge),
    nameEdited: Boolean(contact.nameEdited),
    accepted: contact.accepted !== false,
    blocked: Boolean(contact.blocked),
    notifications: contact.notifications !== false,
    notificationMode: ["all", "mentions", "off"].includes(contact.notificationMode) ? contact.notificationMode : "all",
    mutedUntil: normalizeAdminDate(contact.mutedUntil),
    shareReadReceipts: contact.shareReadReceipts !== false,
    shareTyping: contact.shareTyping !== false,
    sharePresence: contact.sharePresence !== false,
    pinned: Boolean(contact.pinned),
    chatBackground: sanitizeHexColor(contact.chatBackground),
    updatedAt: String(contact.updatedAt || contact.createdAt || new Date().toISOString()).slice(0, 40)
  };
}

function sanitizeHexColor(value = "") {
  const color = String(value || "").trim();
  return /^#[0-9a-f]{6}$/i.test(color) ? color : "";
}

function mergeSyncedContacts(existing = [], incoming = []) {
  const contacts = new Map();
  for (const contact of sanitizeSyncedContacts(existing)) contacts.set(contact.id, contact);
  for (const contact of sanitizeSyncedContacts(incoming)) {
    contacts.set(contact.id, {
      ...(contacts.get(contact.id) || {}),
      ...contact,
      updatedAt: new Date().toISOString()
    });
  }
  return [...contacts.values()].slice(0, 1000);
}

function normalizeAdminDate(value) {
  if (!value) return "";
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp > Date.now() ? new Date(timestamp).toISOString() : "";
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

async function batchedUpstashGets(keys = []) {
  const results = [];
  const batchSize = 25;
  for (let index = 0; index < keys.length; index += batchSize) {
    const batch = keys.slice(index, index + batchSize);
    results.push(...await upstashPipeline(batch.map((key) => ["GET", key])));
  }
  return results;
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

function sanitizePrice(value, fallback, { min = 0, max = 1_000_000 } = {}) {
  const parsed = Math.round(Number(value));
  return Number.isSafeInteger(parsed) ? Math.max(min, Math.min(max, parsed)) : fallback;
}

function normalizePricing(candidate = {}) {
  const next = {};
  for (const [key, fallback] of Object.entries(DEFAULT_PRICING)) {
    const isSeconds = key.endsWith("Seconds");
    next[key] = sanitizePrice(candidate[key], fallback, { min: isSeconds ? 0 : 0, max: isSeconds ? 86_400 : 1_000_000 });
  }
  return next;
}

function publicPricing() {
  return { ...pricing, callBlockSeconds: CALL_BLOCK_SECONDS };
}

async function loadPricingConfig() {
  let stored = null;
  if (redis) stored = await redis.get(PRICING_STORAGE_KEY);
  else if (upstashRestEnabled) stored = await upstashCommand(["GET", PRICING_STORAGE_KEY]);
  if (stored) pricing = normalizePricing(safeJsonParse(stored) || {});
  return pricing;
}

async function savePricingConfig(candidate = {}) {
  pricing = normalizePricing({ ...pricing, ...candidate });
  const payload = JSON.stringify(pricing);
  if (redis) await redis.set(PRICING_STORAGE_KEY, payload);
  if (upstashRestEnabled) await upstashCommand(["SET", PRICING_STORAGE_KEY, payload]);
  return pricing;
}

function broadcastPricingUpdated() {
  for (const sockets of clients.values()) {
    for (const socket of sockets) send(socket, { type: "pricing-updated", pricing: publicPricing() });
  }
}

// Serializes wallet mutations inside this server process. Render currently runs
// one Bypassium server instance, while each mutation is persisted as one Redis
// MULTI/Upstash pipeline so balances and ledger indexes move together.
function withWalletLock(operation) {
  const run = walletOperationQueue.then(operation, operation);
  walletOperationQueue = run.catch(() => {});
  return run;
}

function cleanWalletAmount(value) {
  const amount = Number(value);
  return Number.isSafeInteger(amount) && amount > 0 ? amount : 0;
}

function walletRecord(peerId, value = {}) {
  return {
    accountId: peerId,
    balance: Math.max(0, Math.round(Number(value.balance ?? WALLET_STARTING_BALANCE))),
    frozen: Boolean(value.frozen),
    freezeReason: String(value.freezeReason || "").slice(0, 240),
    initializedAt: String(value.initializedAt || new Date().toISOString()),
    updatedAt: String(value.updatedAt || new Date().toISOString())
  };
}

async function readWallet(peerId) {
  const clean = cleanPeerId(peerId);
  if (!clean) return null;
  if (memoryWallets.has(clean)) return walletRecord(clean, memoryWallets.get(clean));
  let stored = null;
  if (redis) stored = await redis.get(walletKey(clean));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", walletKey(clean)]);
  if (stored) {
    const record = walletRecord(clean, JSON.parse(stored));
    memoryWallets.set(clean, record);
    return record;
  }
  const record = walletRecord(clean);
  await writeWallet(record);
  return record;
}

async function writeWallet(record) {
  const clean = walletRecord(record.accountId, record);
  memoryWallets.set(clean.accountId, clean);
  const serialized = JSON.stringify(clean);
  if (redis) await redis.set(walletKey(clean.accountId), serialized);
  if (upstashRestEnabled) await upstashCommand(["SET", walletKey(clean.accountId), serialized]);
  return clean;
}

async function readWalletTransaction(transactionId) {
  const id = String(transactionId || "").trim();
  if (!id) return null;
  if (memoryWalletTransactions.has(id)) return memoryWalletTransactions.get(id);
  let stored = null;
  if (redis) stored = await redis.get(walletTransactionKey(id));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", walletTransactionKey(id)]);
  if (!stored) return null;
  const record = JSON.parse(stored);
  memoryWalletTransactions.set(id, record);
  return record;
}

async function persistWalletMutation(wallets, transaction) {
  const cleanWallets = wallets.map((item) => walletRecord(item.accountId, item));
  memoryWalletTransactions.set(transaction.transactionId, transaction);
  for (const wallet of cleanWallets) {
    memoryWallets.set(wallet.accountId, wallet);
    if (!memoryWalletIndexes.has(wallet.accountId)) memoryWalletIndexes.set(wallet.accountId, []);
    const index = memoryWalletIndexes.get(wallet.accountId);
    if (!index.includes(transaction.transactionId)) index.unshift(transaction.transactionId);
    if (index.length > 500) index.length = 500;
  }
  const commands = [
    ["SET", walletTransactionKey(transaction.transactionId), JSON.stringify(transaction)],
    ...cleanWallets.flatMap((wallet) => [
      ["SET", walletKey(wallet.accountId), JSON.stringify(wallet)],
      ["ZADD", walletTransactionIndexKey(wallet.accountId), Date.parse(transaction.createdAt) || Date.now(), transaction.transactionId]
    ])
  ];
  if (redis) {
    const multi = redis.multi();
    for (const command of commands) multi.call(...command);
    await multi.exec();
  }
  if (upstashRestEnabled) await upstashPipeline(commands);
  return transaction;
}

// Updates a pending ledger entry without indexing it a second time.
async function updateWalletTransaction(transaction) {
  memoryWalletTransactions.set(transaction.transactionId, transaction);
  if (redis) await redis.set(walletTransactionKey(transaction.transactionId), JSON.stringify(transaction));
  if (upstashRestEnabled) await upstashCommand(["SET", walletTransactionKey(transaction.transactionId), JSON.stringify(transaction)]);
  return transaction;
}

function attachmentPrice(bytes) {
  const size = Math.max(0, Math.round(Number(bytes) || 0));
  if (!size) return 0;
  const tiers = [
    [256 * 1024, pricing.attachmentUpTo256Kb],
    [1024 * 1024, pricing.attachmentUpTo1Mb],
    [5 * 1024 * 1024, pricing.attachmentUpTo5Mb],
    [10 * 1024 * 1024, pricing.attachmentUpTo10Mb],
    [Number.MAX_SAFE_INTEGER, pricing.attachmentOver10Mb]
  ];
  return tiers.find(([limit]) => size <= limit)?.[1] || 0;
}

function attachmentTransactionId(senderId, messageId) {
  return `attachment_${senderId}_${String(messageId || "").replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 70)}`;
}

async function reserveAttachmentCharge(senderId, messageId, bytes, contentType = "attachment") {
  const amount = attachmentPrice(bytes);
  if (!amount) return null;
  const transactionId = attachmentTransactionId(senderId, messageId);
  const prior = await readWalletTransaction(transactionId);
  if (prior) return prior;
  return withWalletLock(async () => {
    const duplicate = await readWalletTransaction(transactionId);
    if (duplicate) return duplicate;
    const wallet = await readWallet(senderId);
    if (wallet.frozen) throw new Error(`Your wallet is frozen${wallet.freezeReason ? `: ${wallet.freezeReason}` : "."}`);
    if (wallet.balance < amount) throw new Error(`This attachment costs ${amount} B-Coins after delivery. You need ${amount - wallet.balance} more.`);
    const now = new Date().toISOString();
    wallet.balance -= amount;
    wallet.updatedAt = now;
    const transaction = {
      transactionId,
      type: "attachment",
      status: "pending",
      senderId,
      recipientId: "delivery",
      amount,
      reservedAmount: amount,
      attachmentBytes: Math.max(0, Math.round(Number(bytes) || 0)),
      contentType: String(contentType || "attachment").slice(0, 40),
      messageId: String(messageId || "").slice(0, 100),
      caption: `${contentType || "Attachment"} delivery reservation`,
      reason: "Charged only after successful delivery",
      createdAt: now,
      updatedAt: now
    };
    await persistWalletMutation([wallet], transaction);
    return transaction;
  });
}

async function settleAttachmentCharge(envelope) {
  if (!envelope?.attachmentTransactionId) return null;
  return withWalletLock(async () => {
    const transaction = await readWalletTransaction(envelope.attachmentTransactionId);
    if (!transaction || transaction.status !== "pending") return transaction;
    transaction.status = "completed";
    transaction.recipientId = String(envelope.from === envelope.to ? "delivery" : envelope.to || "delivery");
    transaction.deliveredAt = new Date().toISOString();
    transaction.updatedAt = transaction.deliveredAt;
    await updateWalletTransaction(transaction);
    return transaction;
  });
}

async function refundAttachmentCharge(transactionId, reason = "Attachment was not delivered") {
  if (!transactionId) return null;
  return withWalletLock(async () => {
    const transaction = await readWalletTransaction(transactionId);
    if (!transaction || transaction.status !== "pending") return transaction;
    const wallet = await readWallet(transaction.senderId);
    const now = new Date().toISOString();
    wallet.balance += transaction.amount;
    wallet.updatedAt = now;
    transaction.status = "refunded";
    transaction.refundedAt = now;
    transaction.updatedAt = now;
    transaction.refundReason = String(reason).slice(0, 180);
    const refund = {
      transactionId: `refund_${transactionId}`,
      type: "attachment_refund",
      status: "completed",
      senderId: "system",
      recipientId: transaction.senderId,
      amount: transaction.amount,
      caption: "Attachment delivery refund",
      reason: transaction.refundReason,
      reversesTransactionId: transactionId,
      createdAt: now
    };
    await updateWalletTransaction(transaction);
    await persistWalletMutation([wallet], refund);
    return refund;
  });
}

function callUsageDate() {
  return new Date().toISOString().slice(0, 10);
}

async function readCallFreeUsage(peerId) {
  const key = callFreeUsageKey(peerId, callUsageDate());
  if (memoryCallFreeUsage.has(key)) return Number(memoryCallFreeUsage.get(key) || 0);
  let value = 0;
  if (redis) value = Number(await redis.get(key) || 0);
  if (upstashRestEnabled) value = Number(await upstashCommand(["GET", key]) || 0);
  memoryCallFreeUsage.set(key, value);
  return value;
}

async function writeCallFreeUsage(peerId, seconds) {
  const key = callFreeUsageKey(peerId, callUsageDate());
  const value = Math.max(0, Math.min(pricing.directCallDailyFreeSeconds, Math.round(Number(seconds) || 0)));
  memoryCallFreeUsage.set(key, value);
  if (redis) await redis.set(key, value, "EX", 172800);
  if (upstashRestEnabled) await upstashCommand(["SET", key, value, "EX", 172800]);
}

function publicCallBilling(session) {
  return {
    callId: session.callId,
    remainingSeconds: Math.max(0, Math.ceil(session.remainingSeconds)),
    freeSeconds: Math.max(0, Math.ceil(session.freeRemaining || 0)),
    blockSeconds: CALL_BLOCK_SECONDS,
    blockCost: session.blockCost,
    dailyFreeSeconds: session.mode === "group" ? 0 : pricing.directCallDailyFreeSeconds,
    mode: session.mode || "direct",
    connected: Boolean(session.connectedAt),
    participants: [...session.participants]
  };
}

async function saveCallBilling(session) {
  memoryCallBilling.set(session.callId, session);
  const stored = { ...session, participants: [...session.participants] };
  if (redis) await redis.set(callBillingKey(session.callId), JSON.stringify(stored), "EX", CALL_BILLING_TTL_SECONDS);
  if (upstashRestEnabled) await upstashCommand(["SET", callBillingKey(session.callId), JSON.stringify(stored), "EX", CALL_BILLING_TTL_SECONDS]);
}

async function getCallBilling(callId) {
  if (memoryCallBilling.has(callId)) return memoryCallBilling.get(callId);
  let stored = null;
  if (redis) stored = await redis.get(callBillingKey(callId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", callBillingKey(callId)]);
  if (!stored) return null;
  const parsed = JSON.parse(stored);
  parsed.participants = new Set(parsed.participants || []);
  memoryCallBilling.set(callId, parsed);
  return parsed;
}

async function reserveCallBlocks(peerId, callId, blocks, session) {
  const amount = session.blockCost * blocks;
  const transactionId = `call_${callId}_${peerId}_${randomUUID()}`;
  return withWalletLock(async () => {
    const wallet = await readWallet(peerId);
    if (wallet.frozen) throw new Error(`Your wallet is frozen${wallet.freezeReason ? `: ${wallet.freezeReason}` : "."}`);
    if (wallet.balance < amount) throw new Error(`You need ${amount - wallet.balance} more B-Coins for ${blocks} call minute${blocks === 1 ? "" : "s"}.`);
    const now = new Date().toISOString();
    wallet.balance -= amount;
    wallet.updatedAt = now;
    const transaction = { transactionId, type: "call_reservation", status: "pending", senderId: peerId, recipientId: "call", amount, reservedAmount: amount, callId, seconds: blocks * CALL_BLOCK_SECONDS, caption: `${blocks} call minute${blocks === 1 ? "" : "s"} reserved`, reason: "Unused paid call time is refunded", createdAt: now, updatedAt: now };
    await persistWalletMutation([wallet], transaction);
    session.contributions.push({ peerId, transactionId, credits: amount, seconds: blocks * CALL_BLOCK_SECONDS, usedSeconds: 0 });
    session.remainingSeconds += blocks * CALL_BLOCK_SECONDS;
    await notifyWalletUpdated(peerId, transaction);
    return transaction;
  });
}

async function startCallBilling(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const requestId = String(message.requestId || "");
  const targetId = cleanPeerId(message.targetId);
  const callId = String(message.callId || "").trim().slice(0, 80);
  if (!peerId || !targetId || targetId === peerId || !callId) return send(socket, { type: "call-billing-start-result", requestId, ok: false, message: "Call billing details are invalid." });
  if (!clients.get(targetId)?.size) return send(socket, { type: "call-billing-start-result", requestId, ok: false, message: "That contact is not online. You were not charged." });
  const session = await ensureCallBilling(peerId, targetId, callId);
  send(socket, { type: "call-billing-start-result", requestId, ok: true, billing: publicCallBilling(session), wallet: await walletSummary(peerId) });
}

async function ensureCallBilling(peerId, targetId, callId) {
  let session = await getCallBilling(callId);
  if (session) return session;
  const used = await readCallFreeUsage(peerId);
  const free = Math.max(0, pricing.directCallDailyFreeSeconds - used);
  session = { callId, mode: "direct", blockCost: pricing.directCallPerMinute, ownerId: peerId, participants: new Set([peerId, targetId]), remainingSeconds: free, freeAllocated: free, freeRemaining: free, freeOwnerId: peerId, contributions: [], createdAt: Date.now(), connectedAt: 0, lastTickAt: 0 };
  if (!free) await reserveCallBlocks(peerId, callId, 1, session);
  await saveCallBilling(session);
  return session;
}

async function ensureGroupCallBilling(peerId, group, callId) {
  let session = await getCallBilling(callId);
  if (session) return session;
  session = {
    callId,
    mode: "group",
    blockCost: pricing.groupCallPerMinute,
    ownerId: peerId,
    participants: new Set(group.members),
    remainingSeconds: 0,
    freeAllocated: 0,
    freeRemaining: 0,
    freeOwnerId: "",
    contributions: [],
    createdAt: Date.now(),
    connectedAt: 0,
    lastTickAt: 0
  };
  await reserveCallBlocks(peerId, callId, 1, session);
  await saveCallBilling(session);
  return session;
}

async function topUpCallBilling(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const requestId = String(message.requestId || "");
  const callId = String(message.callId || "").trim().slice(0, 80);
  const blocks = Math.max(1, Math.min(10, Math.round(Number(message.blocks) || 1)));
  const session = await getCallBilling(callId);
  if (!peerId || !session || !session.participants.has(peerId)) return send(socket, { type: "call-billing-top-up-result", requestId, ok: false, message: "That active call could not be found." });
  try {
    const transaction = await reserveCallBlocks(peerId, callId, blocks, session);
    await saveCallBilling(session);
    broadcastCallBilling(session);
    send(socket, { type: "call-billing-top-up-result", requestId, ok: true, billing: publicCallBilling(session), transaction, wallet: await walletSummary(peerId) });
  } catch (error) {
    send(socket, { type: "call-billing-top-up-result", requestId, ok: false, message: error.message });
  }
}

async function syncCallBilling(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const requestId = String(message.requestId || "");
  const session = await getCallBilling(String(message.callId || "").trim().slice(0, 80));
  if (!peerId || !session?.participants.has(peerId)) return send(socket, { type: "call-billing-sync-result", requestId, ok: false, message: "That active call could not be found." });
  send(socket, { type: "call-billing-sync-result", requestId, ok: true, billing: publicCallBilling(session) });
}

function broadcastCallBilling(session) {
  for (const peerId of session.participants) sendToClient(peerId, { type: "call-billing-updated", billing: publicCallBilling(session) });
}

async function finishCallBilling(session, reason = "Call ended") {
  if (!session || session.finishedAt) return;
  session.finishedAt = Date.now();
  const freeUsed = Math.max(0, Number(session.freeAllocated || 0) - Number(session.freeRemaining || 0));
  if (session.freeOwnerId && freeUsed) await writeCallFreeUsage(session.freeOwnerId, (await readCallFreeUsage(session.freeOwnerId)) + freeUsed);
  for (const contribution of session.contributions) {
    const original = await readWalletTransaction(contribution.transactionId);
    if (!original || original.status !== "pending") continue;
    const billedSeconds = Math.min(contribution.seconds, Math.ceil(contribution.usedSeconds / 5) * 5);
    const usedCredits = Math.min(contribution.credits, Math.ceil((contribution.credits * billedSeconds) / contribution.seconds));
    const refund = contribution.credits - usedCredits;
    original.status = "completed";
    original.amount = usedCredits;
    original.usedSeconds = contribution.usedSeconds;
    original.updatedAt = new Date().toISOString();
    original.reason = reason;
    await updateWalletTransaction(original);
    if (refund > 0) {
      const wallet = await readWallet(contribution.peerId);
      wallet.balance += refund;
      wallet.updatedAt = original.updatedAt;
      await persistWalletMutation([wallet], { transactionId: `refund_${contribution.transactionId}`, type: "call_refund", status: "completed", senderId: "system", recipientId: contribution.peerId, amount: refund, callId: session.callId, caption: "Unused call time refunded", reason, reversesTransactionId: contribution.transactionId, createdAt: original.updatedAt });
      await notifyWalletUpdated(contribution.peerId);
    }
  }
  memoryCallBilling.delete(session.callId);
  if (redis) await redis.del(callBillingKey(session.callId));
  if (upstashRestEnabled) await upstashCommand(["DEL", callBillingKey(session.callId)]);
}

// Consumes call allowance centrally so both clients display the same timer.
setInterval(() => {
  void (async () => {
    for (const session of memoryCallBilling.values()) {
      if (!session.connectedAt || session.finishedAt) continue;
      const now = Date.now();
      const elapsed = Math.max(0, Math.floor((now - (session.lastTickAt || session.connectedAt)) / 1000));
      if (!elapsed) continue;
      session.lastTickAt = now;
      let remaining = Math.min(elapsed, session.remainingSeconds);
      const freeUsed = Math.min(remaining, session.freeRemaining || 0);
      session.freeRemaining = Math.max(0, (session.freeRemaining || 0) - freeUsed);
      remaining -= freeUsed;
      for (const contribution of session.contributions) {
        if (!remaining) break;
        const available = contribution.seconds - contribution.usedSeconds;
        const used = Math.min(available, remaining);
        contribution.usedSeconds += used;
        remaining -= used;
      }
      session.remainingSeconds = Math.max(0, session.remainingSeconds - elapsed);
      await saveCallBilling(session);
      broadcastCallBilling(session);
      if (session.remainingSeconds <= 0) {
        for (const peerId of session.participants) sendToClient(peerId, { type: "call-billing-ended", callId: session.callId, reason: "Call time ran out. Top up B-Coins to call again." });
        await finishCallBilling(session, "Call allowance used");
      }
    }
  })().catch((error) => console.error("Call billing timer failed:", error.message));
}, 1000).unref?.();

async function walletHistory(peerId, limit = WALLET_HISTORY_LIMIT) {
  const clean = cleanPeerId(peerId);
  const safeLimit = Math.max(1, Math.min(200, Math.round(Number(limit) || WALLET_HISTORY_LIMIT)));
  let ids = memoryWalletIndexes.get(clean) || [];
  if (redis) ids = await redis.zrevrange(walletTransactionIndexKey(clean), 0, safeLimit - 1);
  if (upstashRestEnabled) ids = await upstashCommand(["ZREVRANGE", walletTransactionIndexKey(clean), 0, safeLimit - 1]) || [];
  const records = [];
  for (const id of ids.slice(0, safeLimit)) {
    const transaction = await readWalletTransaction(id);
    if (transaction) records.push(transaction);
  }
  return records;
}

async function walletSummary(peerId, limit = WALLET_HISTORY_LIMIT) {
  const wallet = await readWallet(peerId);
  if (!wallet) return null;
  return {
    ...wallet,
    startingBalance: WALLET_STARTING_BALANCE,
    maximumPayment: WALLET_MAX_TRANSFER,
    dailyTransferLimit: WALLET_DAILY_TRANSFER_LIMIT,
    history: await walletHistory(peerId, limit)
  };
}

async function notifyWalletUpdated(peerId, transaction = null) {
  const wallet = await walletSummary(peerId);
  sendToClient(peerId, { type: "wallet-updated", wallet, transaction });
}

async function syncWallet(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  if (!peerId) return;
  send(socket, { type: "wallet-sync-result", requestId: String(message.requestId || ""), ok: true, wallet: await walletSummary(peerId) });
}

async function dailyWalletSpend(peerId) {
  const key = walletDailySpendKey(peerId);
  if (memoryWalletDailySpend.has(key)) return memoryWalletDailySpend.get(key);
  let value = 0;
  if (redis) value = Number(await redis.get(key) || 0);
  if (upstashRestEnabled) value = Number(await upstashCommand(["GET", key]) || 0);
  memoryWalletDailySpend.set(key, value);
  return value;
}

async function setDailyWalletSpend(peerId, amount) {
  const key = walletDailySpendKey(peerId);
  memoryWalletDailySpend.set(key, amount);
  if (redis) await redis.set(key, amount, "EX", 172800);
  if (upstashRestEnabled) await upstashCommand(["SET", key, amount, "EX", 172800]);
}

async function payWalletUser(socket, message = {}) {
  const senderId = getRegisteredSender(socket);
  const requestId = String(message.requestId || "");
  if (!senderId) return;
  if (!allowUserAction(socket, "wallet")) return send(socket, { type: "wallet-pay-result", requestId, ok: false, message: "Too many wallet requests. Try again shortly." });
  const recipientId = cleanPeerId(message.recipientId);
  const amount = cleanWalletAmount(message.amount);
  const transactionId = String(message.clientRequestId || "").trim().slice(0, 80);
  const caption = String(message.caption || "").trim().slice(0, 300);
  if (!recipientId || recipientId === senderId) return send(socket, { type: "wallet-pay-result", requestId, ok: false, message: "Choose another Bypassium account." });
  if (!amount || amount > WALLET_MAX_TRANSFER) return send(socket, { type: "wallet-pay-result", requestId, ok: false, message: `Payments must be whole B-Coins from 1 to ${WALLET_MAX_TRANSFER.toLocaleString()}.` });
  if (!/^[A-Za-z0-9_-]{16,80}$/.test(transactionId)) return send(socket, { type: "wallet-pay-result", requestId, ok: false, message: "That payment request is invalid." });
  const existing = await readWalletTransaction(transactionId);
  if (existing) return send(socket, { type: "wallet-pay-result", requestId, ok: true, duplicate: true, transaction: existing, wallet: await walletSummary(senderId) });
  const [senderBlock, recipientBlock, recipientAccount, contacts] = await Promise.all([
    accountBlockInfo(senderId, "send"), accountBlockInfo(recipientId, "send"), getAccount(recipientId), getSyncedContacts(senderId)
  ]);
  if (senderBlock) return send(socket, { type: "wallet-pay-result", requestId, ok: false, message: senderBlock.message });
  if (recipientBlock) return send(socket, { type: "wallet-pay-result", requestId, ok: false, message: "That account cannot receive payments right now." });
  if (!recipientAccount && !await getPublicKey(recipientId)) return send(socket, { type: "wallet-pay-result", requestId, ok: false, message: "That account no longer exists." });
  const contact = contacts.find((item) => item.id === recipientId);
  if (!contact || contact.accepted === false || contact.blocked) return send(socket, { type: "wallet-pay-result", requestId, ok: false, message: "You can only pay accepted, unblocked contacts." });
  try {
    const transaction = await withWalletLock(async () => {
      const duplicate = await readWalletTransaction(transactionId);
      if (duplicate) return duplicate;
      const sender = await readWallet(senderId);
      const recipient = await readWallet(recipientId);
      if (sender.frozen) throw new Error(`Your wallet is frozen${sender.freezeReason ? `: ${sender.freezeReason}` : "."}`);
      if (recipient.frozen) throw new Error("That wallet is frozen and cannot receive payments.");
      if (sender.balance < amount) throw new Error("You do not have enough B-Coins.");
      const spent = await dailyWalletSpend(senderId);
      if (spent + amount > WALLET_DAILY_TRANSFER_LIMIT) throw new Error("This payment would exceed your daily transfer limit.");
      const now = new Date().toISOString();
      sender.balance -= amount; sender.updatedAt = now;
      recipient.balance += amount; recipient.updatedAt = now;
      const record = { transactionId, type: "payment", status: "completed", senderId, recipientId, amount, caption, reason: "Payment", createdAt: now };
      await persistWalletMutation([sender, recipient], record);
      await setDailyWalletSpend(senderId, spent + amount);
      return record;
    });
    send(socket, { type: "wallet-pay-result", requestId, ok: true, transaction, wallet: await walletSummary(senderId) });
    await notifyWalletUpdated(recipientId, transaction);
  } catch (error) {
    send(socket, { type: "wallet-pay-result", requestId, ok: false, message: error.message || "Payment failed." });
  }
}

async function startArcadeRound(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const requestId = String(message.requestId || "");
  if (!peerId) return;
  if (String(message.gameId || "") !== "animated-memory") return send(socket, { type: "arcade-round-result", requestId, ok: false, message: "That game is not available." });
  const roundId = randomUUID();
  const round = { roundId, peerId, gameId: "animated-memory", startedAt: Date.now(), deckFlipPurchased: false };
  memoryArcadeRounds.set(roundId, round);
  if (redis) await redis.set(arcadeRoundKey(roundId), JSON.stringify(round), "EX", 900);
  if (upstashRestEnabled) await upstashCommand(["SET", arcadeRoundKey(roundId), JSON.stringify(round), "EX", 900]);
  send(socket, { type: "arcade-round-result", requestId, ok: true, roundId, startedAt: round.startedAt });
}

async function getArcadeRound(roundId) {
  if (memoryArcadeRounds.has(roundId)) return memoryArcadeRounds.get(roundId);
  let stored = null;
  if (redis) stored = await redis.get(arcadeRoundKey(roundId));
  if (upstashRestEnabled) stored = await upstashCommand(["GET", arcadeRoundKey(roundId)]);
  if (!stored) return null;
  const round = JSON.parse(stored);
  memoryArcadeRounds.set(roundId, round);
  return round;
}

async function saveArcadeRound(round) {
  memoryArcadeRounds.set(round.roundId, round);
  if (redis) await redis.set(arcadeRoundKey(round.roundId), JSON.stringify(round), "EX", 900);
  if (upstashRestEnabled) await upstashCommand(["SET", arcadeRoundKey(round.roundId), JSON.stringify(round), "EX", 900]);
}

async function purchaseArcadeItem(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const requestId = String(message.requestId || "");
  const roundId = String(message.roundId || "");
  if (!peerId) return;
  try {
    const transaction = await withWalletLock(async () => {
      const round = await getArcadeRound(roundId);
      if (!round || round.peerId !== peerId || round.gameId !== "animated-memory") throw new Error("That Memory Flip round has expired.");
      if (String(message.itemId || "") !== "memory-deck-flip") throw new Error("That arcade item is not available.");
      if (round.deckFlipPurchased) throw new Error("Deck Flip can only be used once per round.");
      const wallet = await readWallet(peerId);
      if (wallet.frozen) throw new Error(`Your wallet is frozen${wallet.freezeReason ? `: ${wallet.freezeReason}` : "."}`);
      if (wallet.balance < pricing.memoryDeckFlip) throw new Error(`You need ${pricing.memoryDeckFlip} B-Coins for Deck Flip.`);
      const now = new Date().toISOString();
      wallet.balance -= pricing.memoryDeckFlip; wallet.updatedAt = now;
      round.deckFlipPurchased = true;
      await saveArcadeRound(round);
      const record = { transactionId: randomUUID(), type: "arcade_purchase", status: "completed", senderId: peerId, recipientId: "", amount: pricing.memoryDeckFlip, caption: "Memory Flip: Deck Flip", reason: "Arcade purchase", gameId: round.gameId, roundId, createdAt: now };
      await persistWalletMutation([wallet], record);
      return record;
    });
    send(socket, { type: "arcade-purchase-result", requestId, ok: true, transaction, wallet: await walletSummary(peerId) });
    await notifyWalletUpdated(peerId, transaction);
  } catch (error) {
    send(socket, { type: "arcade-purchase-result", requestId, ok: false, message: error.message || "Purchase failed." });
  }
}

function memoryRewardForElapsed(elapsedMs) {
  if (elapsedMs <= 10_000) return pricing.memoryUnder10Seconds;
  if (elapsedMs <= 20_000) return pricing.memoryUnder20Seconds;
  if (elapsedMs <= 30_000) return pricing.memoryUnder30Seconds;
  if (elapsedMs <= 40_000) return pricing.memoryUnder40Seconds;
  if (elapsedMs <= 50_000) return pricing.memoryUnder50Seconds;
  if (elapsedMs <= 60_000) return pricing.memoryUnder60Seconds;
  return pricing.memoryOver60Seconds;
}

async function claimArcadeReward(socket, message = {}) {
  const peerId = getRegisteredSender(socket);
  const requestId = String(message.requestId || "");
  const roundId = String(message.roundId || "");
  const claimId = String(message.claimId || "").slice(0, 80);
  const elapsedMs = Math.round(Number(message.elapsedMs));
  if (!peerId) return;
  if (!/^[A-Za-z0-9_-]{16,80}$/.test(claimId)) return send(socket, { type: "arcade-reward-result", requestId, ok: false, message: "That reward claim is invalid." });
  const prior = await readWalletTransaction(claimId);
  if (prior) return send(socket, { type: "arcade-reward-result", requestId, ok: true, duplicate: true, transaction: prior, reward: prior.amount, wallet: await walletSummary(peerId) });
  const cooldownKey = arcadeRewardCooldownKey(peerId, "animated-memory");
  let lastClaimAt = Number(memoryArcadeCooldowns.get(cooldownKey) || 0);
  if (redis && !lastClaimAt) lastClaimAt = Number(await redis.get(cooldownKey) || 0);
  if (upstashRestEnabled && !lastClaimAt) lastClaimAt = Number(await upstashCommand(["GET", cooldownKey]) || 0);
  if (lastClaimAt && Date.now() - lastClaimAt < MEMORY_REWARD_COOLDOWN_MS) {
    return send(socket, { type: "arcade-reward-result", requestId, ok: false, message: "Memory Flip rewards are cooling down. Start the next round in a few seconds." });
  }
  try {
    const transaction = await withWalletLock(async () => {
      const round = await getArcadeRound(roundId);
      if (!round || round.peerId !== peerId || round.gameId !== "animated-memory" || round.claimedAt) throw new Error("That Memory Flip round is invalid or already claimed.");
      if (Number(message.matchedPairs) !== 16 || !Number.isSafeInteger(elapsedMs) || elapsedMs < 3000 || elapsedMs > 600000) throw new Error("That Memory Flip result could not be verified.");
      const serverElapsed = Date.now() - Number(round.startedAt || 0);
      if (serverElapsed + 2500 < elapsedMs || Math.abs(serverElapsed - elapsedMs) > 20_000) throw new Error("That Memory Flip timing could not be verified.");
      const wallet = await readWallet(peerId);
      if (wallet.frozen) throw new Error(`Your wallet is frozen${wallet.freezeReason ? `: ${wallet.freezeReason}` : "."}`);
      const reward = memoryRewardForElapsed(elapsedMs);
      const now = new Date().toISOString();
      wallet.balance += reward; wallet.updatedAt = now;
      round.claimedAt = Date.now();
      await saveArcadeRound(round);
      const record = { transactionId: claimId, type: "game_reward", status: "completed", senderId: "", recipientId: peerId, amount: reward, caption: `Memory Flip cleared in ${(elapsedMs / 1000).toFixed(1)}s`, reason: "Arcade reward", gameId: round.gameId, roundId, elapsedMs, createdAt: now };
      await persistWalletMutation([wallet], record);
      memoryArcadeCooldowns.set(cooldownKey, Date.now());
      if (redis) await redis.set(cooldownKey, Date.now(), "PX", MEMORY_REWARD_COOLDOWN_MS);
      if (upstashRestEnabled) await upstashCommand(["SET", cooldownKey, Date.now(), "PX", MEMORY_REWARD_COOLDOWN_MS]);
      return record;
    });
    send(socket, { type: "arcade-reward-result", requestId, ok: true, transaction, reward: transaction.amount, wallet: await walletSummary(peerId) });
    await notifyWalletUpdated(peerId, transaction);
  } catch (error) {
    send(socket, { type: "arcade-reward-result", requestId, ok: false, message: error.message || "Reward claim failed." });
  }
}

async function adjustWalletByAdmin(peerId, delta, reason) {
  return withWalletLock(async () => {
    const wallet = await readWallet(peerId);
    if (!wallet) throw new Error("Account wallet was not found.");
    if (!Number.isSafeInteger(delta) || delta === 0) throw new Error("Enter a non-zero whole B-Coin adjustment.");
    if (wallet.balance + delta < 0) throw new Error("That adjustment would make the wallet negative.");
    const now = new Date().toISOString();
    wallet.balance += delta; wallet.updatedAt = now;
    const transaction = { transactionId: randomUUID(), type: "admin_adjustment", status: "completed", senderId: delta < 0 ? peerId : "admin", recipientId: delta > 0 ? peerId : "admin", amount: Math.abs(delta), signedAmount: delta, caption: reason, reason, createdAt: now };
    await persistWalletMutation([wallet], transaction);
    return transaction;
  });
}

async function setWalletFrozen(peerId, frozen, reason) {
  return withWalletLock(async () => {
    const wallet = await readWallet(peerId);
    wallet.frozen = Boolean(frozen);
    wallet.freezeReason = wallet.frozen ? String(reason || "Frozen by Bypassium Support").slice(0, 240) : "";
    wallet.updatedAt = new Date().toISOString();
    await writeWallet(wallet);
    return wallet;
  });
}

async function reverseWalletTransaction(transactionId, reason) {
  return withWalletLock(async () => {
    const original = await readWalletTransaction(transactionId);
    if (!original || original.status !== "completed") throw new Error("That completed transaction was not found.");
    const reverseId = `reverse_${transactionId}`;
    const existing = await readWalletTransaction(reverseId);
    if (existing) return existing;
    const now = new Date().toISOString();
    let wallets = [];
    if (original.type === "payment") {
      const sender = await readWallet(original.senderId);
      const recipient = await readWallet(original.recipientId);
      if (recipient.balance < original.amount) throw new Error("The recipient no longer has enough B-Coins to reverse this payment.");
      recipient.balance -= original.amount; sender.balance += original.amount;
      recipient.updatedAt = now; sender.updatedAt = now; wallets = [sender, recipient];
    } else if (original.type === "admin_adjustment") {
      const peerId = original.senderId === "admin" ? original.recipientId : original.senderId;
      const wallet = await readWallet(peerId);
      const delta = -Number(original.signedAmount || 0);
      if (wallet.balance + delta < 0) throw new Error("That reversal would make the wallet negative.");
      wallet.balance += delta; wallet.updatedAt = now; wallets = [wallet];
    } else throw new Error("That transaction type cannot be reversed.");
    const reversal = { transactionId: reverseId, type: "reversal", status: "completed", senderId: original.recipientId, recipientId: original.senderId, amount: original.amount, caption: reason, reason, reversesTransactionId: transactionId, createdAt: now };
    await persistWalletMutation(wallets, reversal);
    return reversal;
  });
}

function sanitizeProfile(profile = {}, stampUpdate = false) {
  const status = activeProfileStatus(profile);
  const cleanProfile = {
    displayName: String(profile?.displayName || "").slice(0, 80),
    profilePicture: sanitizeProfilePicture(profile?.profilePicture),
    badge: sanitizeProfileBadge(profile?.badge),
    joinedAt: String(profile?.joinedAt || "").slice(0, 40),
    quickAddVisible: profile?.quickAddVisible !== false,
    statusText: status.text,
    statusExpiresAt: status.expiresAt
  };
  if (stampUpdate) cleanProfile.updatedAt = new Date().toISOString();
  else if (profile?.updatedAt) cleanProfile.updatedAt = String(profile.updatedAt).slice(0, 40);
  return cleanProfile;
}

function activeProfileStatus(profile = {}) {
  const text = String(profile?.statusText || "").replace(/\s+/g, " ").trim().slice(0, 80);
  if (!text) return { text: "", expiresAt: "" };
  const rawExpiry = String(profile?.statusExpiresAt || "").trim();
  if (!rawExpiry) return { text, expiresAt: "" };
  const timestamp = Date.parse(rawExpiry);
  if (!Number.isFinite(timestamp) || timestamp <= Date.now()) return { text: "", expiresAt: "" };
  return { text, expiresAt: new Date(timestamp).toISOString() };
}

function sanitizeProfileBadge(value = "") {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 32);
}

function sanitizeProfilePicture(value = "") {
  const picture = String(value || "");
  if (!picture) return "";
  if (!picture.startsWith("data:image/")) return "";
  return picture.slice(0, MAX_PROFILE_PICTURE_CHARS);
}

function sanitizeCallDescription(description = null) {
  if (!description || typeof description !== "object") return null;
  const type = String(description.type || "").trim();
  if (!["offer", "answer", "rollback", "pranswer"].includes(type)) return null;
  const clean = {
    type,
    sdp: String(description.sdp || "").slice(0, MAX_CALL_SIGNAL_CHARS)
  };
  if (JSON.stringify(clean).length > MAX_CALL_SIGNAL_CHARS) return null;
  return clean;
}

function sanitizeCallCandidate(candidate = null) {
  if (!candidate || typeof candidate !== "object") return null;
  const clean = {
    candidate: String(candidate.candidate || "").slice(0, 4096),
    sdpMid: candidate.sdpMid == null ? null : String(candidate.sdpMid).slice(0, 64),
    sdpMLineIndex: Number.isFinite(Number(candidate.sdpMLineIndex)) ? Number(candidate.sdpMLineIndex) : null,
    usernameFragment: candidate.usernameFragment == null ? null : String(candidate.usernameFragment).slice(0, 128)
  };
  if (!clean.candidate || JSON.stringify(clean).length > 8192) return null;
  return clean;
}

function sanitizeCallMediaState(media = null) {
  if (!media || typeof media !== "object") return null;
  return {
    cameraEnabled: Boolean(media.cameraEnabled),
    micMuted: Boolean(media.micMuted)
  };
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

function normalizeOwnerResetCode(code = "") {
  return String(code || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/^BYP(?=[0-9A-F]{8}$)/, "BYP-");
}

function validOwnerResetCode(code = "") {
  return /^BYP-[0-9A-F]{8}$/.test(normalizeOwnerResetCode(code));
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
    story: 30,
    "directory-search": 80,
    "account-recovery": 50,
    wallet: 30,
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

function historyTtlSeconds() {
  return Math.max(0, Number(HISTORY_TTL_SECONDS) || 0);
}

function maxHistoryMessagesPerUser() {
  return Math.max(0, Number(MAX_HISTORY_MESSAGES_PER_USER) || 0);
}

function defaultHistorySyncLimit() {
  return Math.max(50, Number(DEFAULT_HISTORY_SYNC_LIMIT) || 300);
}

function maxHistorySyncLimit() {
  return Math.max(defaultHistorySyncLimit(), Number(MAX_HISTORY_SYNC_LIMIT) || 5000);
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

function contactListKey(peerId) {
  return `bypassium:contacts:${peerId}`;
}

function walletKey(peerId) {
  return `bypassium:wallet:${peerId}`;
}

function walletTransactionKey(transactionId) {
  return `bypassium:wallet-transaction:${transactionId}`;
}

function walletTransactionIndexKey(peerId) {
  return `bypassium:wallet-transactions:${peerId}`;
}

function walletDailySpendKey(peerId) {
  return `bypassium:wallet-daily:${peerId}:${new Date().toISOString().slice(0, 10)}`;
}

function callBillingKey(callId) {
  return `bypassium:call-billing:${callId}`;
}

function callFreeUsageKey(peerId, date) {
  return `bypassium:call-free:${peerId}:${date}`;
}

function arcadeRoundKey(roundId) {
  return `bypassium:arcade-round:${roundId}`;
}

function arcadeRewardCooldownKey(peerId, gameId) {
  return `bypassium:arcade-cooldown:${peerId}:${gameId}`;
}

function sessionKey(token) {
  return `bypassium:session:${token}`;
}

function sessionIndexKey(peerId) {
  return `bypassium:sessions:${peerId}`;
}

function restrictionKey(peerId) {
  return `bypassium:restriction:${peerId}`;
}

function ownerResetKey(peerId) {
  return `bypassium:owner-reset:${peerId}`;
}

function adminAuditKey() {
  return "bypassium:admin-audit";
}

function safetyLogKey() {
  return "bypassium:safety-log";
}

function accountIndexKey() {
  return "bypassium:account-index";
}

function accountSearchIndexKey() {
  return "bypassium:account-search-index";
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

function historyIndexKey(peerId) {
  return `bypassium:history-index:${peerId}`;
}

function historyMessageKey(peerId, historyId) {
  return `bypassium:history:${peerId}:${historyId}`;
}

function conversationReadStateKey(peerId, conversationKey) {
  return `bypassium:read-state:${peerId}:${conversationKey}`;
}

function storyKey(storyId) {
  return `bypassium:story:${storyId}`;
}

function storyIndexKey(peerId) {
  return `bypassium:stories:${peerId}`;
}

function storyOwnerIndexKey(peerId) {
  return `bypassium:story-owner:${peerId}`;
}

function storyViewsKey(storyId) {
  return `bypassium:story-views:${storyId}`;
}

function storyViewDetailsKey(storyId) {
  return `bypassium:story-view-details:${storyId}`;
}

function storyReactionsKey(storyId) {
  return `bypassium:story-reactions:${storyId}`;
}

function storyCommentsKey(storyId) {
  return `bypassium:story-comments:${storyId}`;
}

function storySharesKey(storyId) {
  return `bypassium:story-shares:${storyId}`;
}

function socialDraftKey(peerId, kind) {
  return `bypassium:social-draft:${peerId}:${kind}`;
}

function safeJsonParse(value) {
  try {
    return typeof value === "string" ? JSON.parse(value) : value;
  } catch {
    return null;
  }
}

function validEncryptedPayload(value) {
  return Boolean(value && typeof value === "object" && value.iv && value.ciphertext);
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

await loadPricingConfig().catch((error) => console.error("Pricing configuration could not be loaded:", error.message));

server.listen(PORT, () => {
  console.log(`Bypassium message server listening on ${PORT}`);
});
