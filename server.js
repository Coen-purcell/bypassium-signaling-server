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
const DEFAULT_HISTORY_SYNC_LIMIT = Number(process.env.DEFAULT_HISTORY_SYNC_LIMIT || 5000);
const MAX_HISTORY_SYNC_LIMIT = Number(process.env.MAX_HISTORY_SYNC_LIMIT || 50000);
const MAX_PROFILE_PICTURE_CHARS = 18000;
const MAX_UPSTASH_RPUSH_ITEMS = 4;
const MAX_UPSTASH_RPUSH_CHARS = 6_000_000;
const MAX_UPSTASH_COMMAND_CHARS = 8_500_000;
const MAX_QUEUED_ENVELOPE_CHARS = 7_500_000;
const MAX_WEBSOCKET_PAYLOAD_CHARS = 8_500_000;
const REDIS_URL = process.env.REDIS_URL || process.env.RENDER_REDIS_URL || process.env.KEY_VALUE_URL || "";
const UPSTASH_REST_URL = process.env.UPSTASH_REDIS_REST_URL || "";
const UPSTASH_REST_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || "";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
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
const memoryOfflineMessages = new Map();
const memoryHistoryMessages = new Map();
const pendingQueuedEnvelopes = new Map();
const cancelledQueuedEnvelopes = new Set();
let accountIndexHydrated = false;
let accountIndexHydrationPromise = null;
const redis = createRedisClient();
const upstashRestEnabled = Boolean(!redis && UPSTASH_REST_URL && UPSTASH_REST_TOKEN);

const server = http.createServer(async (request, response) => {
  const corsHeaders = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, x-admin-token"
  };
  if (request.method === "OPTIONS") {
    response.writeHead(204, corsHeaders);
    response.end();
    return;
  }

  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

  if (url.pathname === "/health") {
    response.writeHead(200, { ...corsHeaders, "content-type": "application/json" });
    response.end(JSON.stringify({
      ok: true,
      storage: storageMode(),
      onlineClients: clients.size,
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
      if (message.type === "history-sync") await syncHistoryMessages(socket, message);
      if (message.type === "history-backfill") await backfillHistoryMessages(socket, message);
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

    if (request.method === "GET" && url.pathname === "/admin/api/audit") {
      sendJson(response, 200, { ok: true, audit: await getAdminAudit() }, corsHeaders);
      return;
    }

    if (request.method !== "POST") {
      sendJson(response, 405, { ok: false, message: "Method not allowed." }, corsHeaders);
      return;
    }

    const body = await readRequestJson(request);

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

function safeEqualString(first, second) {
  const firstBuffer = Buffer.from(String(first || ""));
  const secondBuffer = Buffer.from(String(second || ""));
  if (firstBuffer.length !== secondBuffer.length || !firstBuffer.length) return false;
  return timingSafeEqual(firstBuffer, secondBuffer);
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
    const state = { token: localStorage.getItem("bypassiumAdminToken") || "", selected: "", selectedPeers: new Set(), searchTimer: 0, searchSeq: 0, profilePictureDraft: "" };
    const $ = (id) => document.getElementById(id);
    $("token").value = state.token;
    $("saveToken").onclick = () => { state.token = $("token").value.trim(); localStorage.setItem("bypassiumAdminToken", state.token); refreshAll(); };
    $("searchBtn").onclick = () => searchAccounts();
    $("search").addEventListener("input", () => scheduleAccountSearch());
    $("search").addEventListener("keydown", (event) => { if (event.key === "Enter") searchAccounts(); });
    $("refreshAudit").onclick = () => loadAudit();
    $("selectAll").onchange = () => toggleShownSelection($("selectAll").checked);
    $("clearSelected").onclick = () => { state.selectedPeers.clear(); updateSelectionUi(); };
    $("bulkDelete").onclick = () => bulkDeleteSelected();

    async function api(path, options = {}) {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);
      const response = await fetch("/admin/api" + path, {
        ...options,
        signal: controller.signal,
        headers: { "content-type": "application/json", authorization: "Bearer " + state.token, ...(options.headers || {}) }
      }).finally(() => clearTimeout(timeout));
      const payload = await response.json().catch(() => ({ ok:false, message:"Bad server response." }));
      if (!response.ok || payload.ok === false) throw new Error(payload.message || "Request failed.");
      return payload;
    }
    async function refreshAll() { await Promise.allSettled([loadStatus(), searchAccounts(), loadAudit()]); }
    async function loadStatus() {
      try {
        const config = await fetch("/admin/api/config").then((r) => r.json());
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
    function clearDetail(message) {
      state.selected = "";
      $("detail").innerHTML = '<h2>Select an account</h2><p class="muted">' + escapeHtml(message || "Search by code or display name, then choose an account to manage.") + '</p>';
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
    async function loadAccount(peerId) {
      try {
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
    function checked(value) { return value ? "checked" : ""; }
    async function postAction(path, body, reload = true) {
      try {
        const payload = await api(path, { method:"POST", body:JSON.stringify(body) });
        toast("Done.");
        if (payload.account) renderDetail(payload.account);
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
      encryptedHistorySync: true,
      persistentEncryptedHistory: historyTtlSeconds() === 0,
      historyBackfill: true,
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
  void storeDirectMessageHistory(senderId, targetId, envelope, {
    senderEncrypted: message.senderEncrypted
  }).catch((error) => console.error("Direct history write failed:", error.message));
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
  if (!(await enforceAccountAction(socket, senderId, "send"))) return;
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
  void storeGroupMessageHistory(senderId, group, {
    messageId,
    sentAt,
    senderProfile,
    senderPublicKeyJwk: socket.publicKeyJwk,
    senderEncrypted,
    recipients
  }).catch((error) => console.error("Group history write failed:", error.message));
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

async function storeDirectMessageHistory(senderId, targetId, envelope, { senderEncrypted = null } = {}) {
  const sentAt = envelope.sentAt || new Date().toISOString();
  await queueHistoryMessage(targetId, {
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
  });

  if (validEncryptedPayload(senderEncrypted)) {
    const targetProfile = await getProfile(targetId) || {};
    const targetPublicKeyJwk = await getPublicKey(targetId);
    await queueHistoryMessage(senderId, {
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
      sentAt
    });
  }
}

async function storeGroupMessageHistory(senderId, group, options = {}) {
  const messageId = String(options.messageId || "");
  if (!messageId) return;
  const sentAt = options.sentAt || new Date().toISOString();
  const recipientById = new Map((options.recipients || []).map((recipient) => [String(recipient.to || ""), recipient]));
  const senderPublicKeyJwk = options.senderPublicKeyJwk || null;

  for (const memberId of group.members || []) {
    if (memberId === senderId) continue;
    const recipient = recipientById.get(memberId);
    if (!validEncryptedPayload(recipient?.encrypted)) continue;
    await queueHistoryMessage(memberId, {
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
    });
  }

  if (validEncryptedPayload(options.senderEncrypted) && senderPublicKeyJwk) {
    await queueHistoryMessage(senderId, {
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
      encrypted: options.senderEncrypted,
      sentAt
    });
  }
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
  const history = await getHistoryMessages(peerId, limit);
  if (history.length) sendHistoryItems(socket, history);
  send(socket, {
    type: "history-sync-complete",
    count: history.length,
    syncedAt: new Date().toISOString()
  });
}

function sendHistoryItems(socket, history) {
  let batch = [];
  for (const item of history) {
    const candidate = [...batch, item];
    const size = JSON.stringify({ type: "history-items", items: candidate }).length;
    if (batch.length && size > MAX_WEBSOCKET_PAYLOAD_CHARS - 300_000) {
      send(socket, { type: "history-items", items: batch });
      batch = [item];
    } else {
      batch = candidate;
    }
  }
  if (batch.length) send(socket, { type: "history-items", items: batch });
}

async function getHistoryMessages(peerId, limit = 500) {
  const requestedLimit = Math.max(0, Number(limit) || 0);
  if (!redis && !upstashRestEnabled) {
    const history = memoryHistoryMessages.get(peerId) || [];
    return requestedLimit ? history.slice(-requestedLimit) : history;
  }
  const ids = await getHistoryIds(peerId);
  const uniqueIds = requestedLimit ? [...new Set(ids)].slice(-requestedLimit) : [...new Set(ids)];
  const messages = [];
  const keptIds = [];
  for (const id of uniqueIds) {
    const stored = await getHistoryMessage(peerId, id);
    if (!stored) continue;
    try {
      messages.push(JSON.parse(stored));
      keptIds.push(id);
    } catch {
      await deleteHistoryMessage(peerId, id);
    }
  }
  if (keptIds.length !== ids.length) await replaceHistoryIds(peerId, keptIds);
  return messages;
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

async function deleteAccountData(peerId) {
  await Promise.all([
    removeAccount(peerId),
    removePublicKey(peerId),
    removeProfile(peerId),
    removeQuickAddProfile(peerId),
    deleteAllQueuedMessages(peerId),
    deleteAllHistoryMessages(peerId),
    removeAccountIndex(peerId)
  ]);
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
    queuedMessages: await countQueuedMessages(peerId),
    sessionCount: await countPeerSessions(peerId),
    groupCount: (await getGroupsForMember(peerId)).length,
    hasPublicKey: Boolean(publicKey),
    storage: storageMode()
  };
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
  if (!stored) return {};
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
    badge: sanitizeProfileBadge(profile?.badge),
    joinedAt: String(profile?.joinedAt || "").slice(0, 40),
    quickAddVisible: profile?.quickAddVisible !== false
  };
  if (stampUpdate) cleanProfile.updatedAt = new Date().toISOString();
  else if (profile?.updatedAt) cleanProfile.updatedAt = String(profile.updatedAt).slice(0, 40);
  return cleanProfile;
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
    "directory-search": 80,
    "account-recovery": 50,
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
  return Math.max(50, Number(DEFAULT_HISTORY_SYNC_LIMIT) || 5000);
}

function maxHistorySyncLimit() {
  return Math.max(defaultHistorySyncLimit(), Number(MAX_HISTORY_SYNC_LIMIT) || 50000);
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

server.listen(PORT, () => {
  console.log(`Bypassium message server listening on ${PORT}`);
});
