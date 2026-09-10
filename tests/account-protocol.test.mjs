import { spawn } from "node:child_process";

const port = 18201 + Math.floor(Math.random() * 500);
const adminToken = "test-admin-token";
const server = spawn(process.execPath, ["server.js"], {
  cwd: new URL("../", import.meta.url),
  env: { ...process.env, PORT: String(port), ADMIN_TOKEN: adminToken, UPSTASH_REDIS_REST_URL: "", UPSTASH_REDIS_REST_TOKEN: "" },
  stdio: ["ignore", "pipe", "pipe"]
});

try {
  await waitForServer();
  const id = String(Math.floor(Math.random() * 900000) + 100000);
  const keys = await keyPair();
  const ws = await openRegisteredSocket(id, keys.publicKeyJwk);
  const recoveryPhrase = "anchor beacon cedar delta ember forest galaxy harbor island jungle lantern maple";
  const created = await request(ws, {
    type: "create-account",
    peerId: id,
    password: "password123",
    publicKeyJwk: keys.publicKeyJwk,
    encryptedIdentityBackup: backup("password"),
    encryptedRecoveryBackup: backup("recovery"),
    recoveryPhrase,
    profile: { displayName: "Protocol Test", quickAddVisible: true }
  });
  assert(created.ok, "create account failed");
  const unauthenticatedReconnect = await openSocket();
  unauthenticatedReconnect.send(JSON.stringify({ type: "register", peerId: id, publicKeyJwk: keys.publicKeyJwk }));
  const authRequired = await once(unauthenticatedReconnect, "account-auth-required");
  assert(authRequired.peerId === id, "password account reconnected without a session token");
  unauthenticatedReconnect.close();
  const sessionSignedIn = await request(ws, { type: "session-sign-in", peerId: id, sessionToken: created.sessionToken });
  assert(sessionSignedIn.ok, "trusted session sign in failed");
  const httpSignInResponse = await fetch(`http://127.0.0.1:${port}/account/sign-in`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ peerId: id, password: "password123" }) });
  const httpSignIn = await httpSignInResponse.json();
  assert(httpSignInResponse.ok && httpSignIn.sessionToken && httpSignIn.encryptedIdentityBackup, "HTTP account sign in failed");
  const httpSessionResponse = await fetch(`http://127.0.0.1:${port}/account/session-sign-in`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ peerId: id, sessionToken: httpSignIn.sessionToken }) });
  const httpSession = await httpSessionResponse.json();
  assert(httpSessionResponse.ok && httpSession.account?.peerId === id, "HTTP saved-session sign in failed");
  const badHttpSignIn = await fetch(`http://127.0.0.1:${port}/account/sign-in`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ peerId: id, password: "wrong-password" }) });
  assert(badHttpSignIn.status === 401, "HTTP sign in accepted an invalid password");
  const wrongContentType = await fetch(`http://127.0.0.1:${port}/account/sign-in`, { method: "POST", headers: { "content-type": "text/plain" }, body: "not-json" });
  assert(wrongContentType.status === 415, "HTTP sign in accepted the wrong content type");
  const adminSearch = await adminRequest(`/accounts?q=${id}`);
  assert(adminSearch.accounts.some((account) => account.peerId === id), "admin account search failed");

  const moderated = await adminRequest("/profile", {
    method: "POST",
    body: { peerId: id, displayName: "Moderated Test", badge: "Updates Director", profilePicture: "data:image/png;base64,a" }
  });
  assert(moderated.account.displayName === "Moderated Test", "admin profile moderation failed");
  assert(moderated.account.badge === "Updates Director", "admin profile badge moderation failed");
  const adminNameSearch = await adminRequest("/accounts?q=moderated");
  assert(adminNameSearch.accounts.some((account) => account.peerId === id && account.badge === "Updates Director"), "admin moderated name search failed");

  ws.send(JSON.stringify({
    type: "publish-profile",
    profile: { displayName: "User Edited Name", profilePicture: "data:image/png;base64,b", quickAddVisible: true }
  }));
  await wait(120);
  const badgeAfterUserProfileUpdate = await adminRequest(`/account?peerId=${id}`);
  assert(badgeAfterUserProfileUpdate.account.badge === "Updates Director", "user profile update removed admin badge");

  const searched = await request(ws, { type: "account-search", query: "user edited", limit: 10 });
  assert(searched.ok && searched.results.some((result) => result.id === id && result.badge === "Updates Director"), "account username search failed");
  const publicWs = await openSocket();
  const publicSearch = await request(publicWs, { type: "account-search", query: "user edited", limit: 10 });
  assert(publicSearch.ok && publicSearch.results.some((result) => result.id === id && result.badge === "Updates Director"), "signed-out account username search failed");
  publicWs.close();
  const httpSearchResponse = await fetch(`http://127.0.0.1:${port}/account/search?q=${encodeURIComponent("user edited")}&limit=10`);
  const httpSearch = await httpSearchResponse.json();
  assert(httpSearchResponse.ok && httpSearch.results.some((result) => result.id === id && result.badge === "Updates Director"), "HTTP public account search failed");
  const httpCodeSearch = await fetch(`http://127.0.0.1:${port}/account/search?q=${id}&limit=10`).then((response) => response.json());
  assert(httpCodeSearch.results.some((result) => result.id === id), "HTTP exact-code account search failed");

  const changed = await request(ws, {
    type: "change-password",
    peerId: id,
    oldPassword: "password123",
    newPassword: "changedpassword123",
    publicKeyJwk: keys.publicKeyJwk,
    encryptedIdentityBackup: backup("changed-password")
  });
  assert(changed.ok && changed.sessionToken, "change password failed");

  const oldPassword = await request(ws, { type: "sign-in", peerId: id, password: "password123" });
  assert(!oldPassword.ok, "old password still works after change");
  const changedPassword = await request(ws, { type: "sign-in", peerId: id, password: "changedpassword123" });
  assert(changedPassword.ok, "new password does not work after change");

  // Large media travels over authenticated HTTP chunks, never through the
  // WebSocket. Repeated chunk PUTs replace the same chunk idempotently.
  const mediaHeaders = { authorization: `Bearer ${changedPassword.sessionToken}`, "x-bypassium-id": id, "content-type": "application/json" };
  const uploadId = crypto.randomUUID();
  const createdUploadResponse = await fetch(`http://127.0.0.1:${port}/media/uploads`, { method: "POST", headers: mediaHeaders, body: JSON.stringify({ uploadId, originalBytes: 700000, name: "large-reel.mp4", mediaType: "video/mp4" }) });
  const createdUpload = await createdUploadResponse.json();
  assert(createdUploadResponse.status === 201 && createdUpload.chunkBytes === 512 * 1024, "media upload session creation failed");
  const firstChunk = new Uint8Array(createdUpload.chunkBytes + 28).fill(0x5a);
  const secondChunk = new Uint8Array(700000 - createdUpload.chunkBytes + 28).fill(0xa5);
  const putChunk = (index, body) => fetch(`http://127.0.0.1:${port}/media/uploads/${uploadId}/chunks/${index}`, { method: "PUT", headers: { authorization: mediaHeaders.authorization, "x-bypassium-id": id, "content-type": "application/octet-stream" }, body });
  assert((await putChunk(0, firstChunk)).ok, "first media chunk failed");
  assert((await putChunk(0, firstChunk)).ok, "idempotent media chunk retry failed");
  assert((await putChunk(1, secondChunk)).ok, "second media chunk failed");
  const completedUploadResponse = await fetch(`http://127.0.0.1:${port}/media/uploads/${uploadId}/complete`, { method: "POST", headers: mediaHeaders, body: "{}" });
  const completedUpload = await completedUploadResponse.json();
  assert(completedUpload.completed, "media upload did not complete");
  const downloaded = new Uint8Array(await (await fetch(completedUpload.mediaUrl)).arrayBuffer());
  assert(downloaded.length === firstChunk.length + secondChunk.length, "completed media ciphertext length changed");
  assert(Buffer.compare(Buffer.from(downloaded.subarray(0, firstChunk.length)), Buffer.from(firstChunk)) === 0, "completed media ciphertext was corrupted");
  const cancelledId = crypto.randomUUID();
  const cancelledCreate = await fetch(`http://127.0.0.1:${port}/media/uploads`, { method: "POST", headers: mediaHeaders, body: JSON.stringify({ uploadId: cancelledId, originalBytes: 1024, name: "cancel.mp4", mediaType: "video/mp4" }) });
  assert(cancelledCreate.ok, "cancellable media upload was not created");
  assert((await fetch(`http://127.0.0.1:${port}/media/uploads/${cancelledId}`, { method: "DELETE", headers: mediaHeaders })).ok, "media cancellation failed");
  const unauthorizedUpload = await fetch(`http://127.0.0.1:${port}/media/uploads`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ originalBytes: 1024 }) });
  assert(unauthorizedUpload.status === 401, "unauthenticated media upload was accepted");
  const oversizedUpload = await fetch(`http://127.0.0.1:${port}/media/uploads`, { method: "POST", headers: mediaHeaders, body: JSON.stringify({ originalBytes: 25 * 1024 * 1024 + 1 }) });
  assert(oversizedUpload.status === 400, "memory-safe media limit was not enforced");

  // Wallet balances are server-owned, payments are idempotent, and game
  // rewards require a live server-issued round.
  const recipientId = String(((Number(id) + 111111) % 900000) + 100000).slice(-6);
  const recipientKeys = await keyPair();
  const recipientWs = await openRegisteredSocket(recipientId, recipientKeys.publicKeyJwk);
  const recipientCreated = await request(recipientWs, {
    type: "create-account", peerId: recipientId, password: "password123", publicKeyJwk: recipientKeys.publicKeyJwk,
    encryptedIdentityBackup: backup("recipient"), encryptedRecoveryBackup: backup("recipient-recovery"),
    recoveryPhrase: "beacon cedar delta ember forest galaxy harbor island jungle lantern maple nectar",
    profile: { displayName: "Wallet Recipient", quickAddVisible: true }
  });
  assert(recipientCreated.ok, "wallet recipient account creation failed");
  ws.send(JSON.stringify({ type: "contacts-sync", contacts: [{ id: recipientId, name: "Wallet Recipient", accepted: true, blocked: false }] }));
  recipientWs.send(JSON.stringify({ type: "contacts-sync", contacts: [{ id, name: "Protocol Test", accepted: true, blocked: false }] }));
  await wait(100);
  const startingWallet = await requestAs(ws, { type: "wallet-sync" }, "wallet-sync-result");
  assert(startingWallet.wallet.balance === 2500, "wallet migration balance was not initialized once");
  const paymentId = `payment_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const paid = await requestAs(ws, { type: "wallet-pay", recipientId, amount: 500, caption: "Wallet protocol test", clientRequestId: paymentId }, "wallet-pay-result");
  assert(paid.ok && paid.wallet.balance === 2000, "wallet payment did not debit sender");
  const duplicate = await requestAs(ws, { type: "wallet-pay", recipientId, amount: 500, caption: "Wallet protocol test", clientRequestId: paymentId }, "wallet-pay-result");
  assert(duplicate.ok && duplicate.duplicate && duplicate.wallet.balance === 2000, "duplicate payment charged twice");
  const recipientWallet = await requestAs(recipientWs, { type: "wallet-sync" }, "wallet-sync-result");
  assert(recipientWallet.wallet.balance === 3000, "wallet payment did not credit recipient");
  const insufficient = await requestAs(ws, { type: "wallet-pay", recipientId, amount: 99999, caption: "Too much", clientRequestId: `payment_${Date.now()}_insufficient` }, "wallet-pay-result");
  assert(!insufficient.ok && /enough/i.test(insufficient.message), "insufficient wallet balance was accepted");
  const round = await requestAs(ws, { type: "arcade-round-start", gameId: "animated-memory" }, "arcade-round-result");
  assert(round.ok && round.roundId, "server did not issue an arcade round");
  await wait(3100);
  const claimId = `reward_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const reward = await requestAs(ws, { type: "arcade-reward", roundId: round.roundId, claimId, elapsedMs: 3100, matchedPairs: 16, mistakes: 0 }, "arcade-reward-result");
  assert(reward.ok && reward.reward === 1160 && reward.wallet.balance === 3160, "verified Memory Flip reward was not credited");
  const replay = await requestAs(ws, { type: "arcade-reward", roundId: round.roundId, claimId, elapsedMs: 3100, matchedPairs: 16, mistakes: 0 }, "arcade-reward-result");
  assert(replay.ok && replay.duplicate && replay.wallet.balance === 3160, "arcade reward replay minted twice");
  const adjustment = await adminRequest("/wallet-adjust", { method: "POST", body: { peerId: id, delta: 40, reason: "Automated wallet test" } });
  assert(adjustment.wallet.balance === 3200, "admin wallet adjustment failed");
  await adminRequest("/wallet-freeze", { method: "POST", body: { peerId: id, frozen: true, reason: "Automated freeze test" } });
  const frozenPayment = await requestAs(ws, { type: "wallet-pay", recipientId, amount: 1, caption: "Frozen", clientRequestId: `payment_${Date.now()}_frozen` }, "wallet-pay-result");
  assert(!frozenPayment.ok && /frozen/i.test(frozenPayment.message), `frozen wallet could still pay: ${JSON.stringify(frozenPayment)}`);
  await adminRequest("/wallet-freeze", { method: "POST", body: { peerId: id, frozen: false, reason: "Automated unfreeze test" } });
  recipientWs.close();

  await adminRequest("/ban", { method: "POST", body: { peerId: id, reason: "test ban" } });
  const authWs = await openSocket();
  const bannedSignIn = await request(authWs, { type: "sign-in", peerId: id, password: "changedpassword123" });
  assert(!bannedSignIn.ok, "banned account could still sign in");
  assert(bannedSignIn.code === "account-banned" && bannedSignIn.banned === true, "banned account response did not include ban metadata");
  await adminRequest("/unban", { method: "POST", body: { peerId: id } });
  const unbannedSignIn = await request(authWs, { type: "sign-in", peerId: id, password: "changedpassword123" });
  assert(unbannedSignIn.ok, "unbanned account could not sign in");

  const forced = await adminRequest("/force-reset", { method: "POST", body: { peerId: id } });
  assert(/^BYP-[0-9A-F]{8}$/.test(forced.resetCode), "admin force reset code failed");
  const checkedForced = await request(authWs, { type: "check-owner-reset-code", resetCode: forced.resetCode });
  assert(checkedForced.ok && checkedForced.peerId === id && checkedForced.account?.peerId === id, "owner reset code lookup failed");
  const resetRequired = await request(authWs, { type: "sign-in", peerId: id, password: "changedpassword123" });
  assert(!resetRequired.ok, "force reset did not block old sign in");
  const ownerResetWs = await openSocket();
  const ownerReset = await request(ownerResetWs, {
    type: "reset-password-with-owner-code",
    peerId: id,
    resetCode: forced.resetCode,
    password: "ownerreset123",
    publicKeyJwk: keys.publicKeyJwk,
    encryptedIdentityBackup: backup("owner-reset")
  });
  assert(ownerReset.ok, "owner reset code password reset failed");
  ownerResetWs.close();
  const ownerResetSignIn = await request(authWs, { type: "sign-in", peerId: id, password: "ownerreset123" });
  assert(ownerResetSignIn.ok, "owner reset password does not work");

  const recovered = await request(authWs, { type: "recover-account", peerId: id, recoveryPhrase });
  assert(recovered.ok && recovered.encryptedRecoveryBackup, "recovery phrase failed");

  const reset = await request(authWs, {
    type: "reset-password-with-recovery",
    peerId: id,
    recoveryPhrase,
    password: "newpassword123",
    publicKeyJwk: keys.publicKeyJwk,
    encryptedIdentityBackup: backup("new-password")
  });
  assert(reset.ok && reset.sessionToken, "password reset failed");

  const signedIn = await request(authWs, { type: "sign-in", peerId: id, password: "newpassword123" });
  assert(signedIn.ok, "sign in after reset failed");

  const chatWs = await openSocket();
  chatWs.send(JSON.stringify({
    type: "register",
    peerId: id,
    publicKeyJwk: keys.publicKeyJwk,
    sessionToken: signedIn.sessionToken
  }));
  const chatRegistered = await once(chatWs, "registered");
  assert(chatRegistered.features?.encryptedHistorySync, "encrypted history feature was not advertised");
  assert(chatRegistered.features?.persistentEncryptedHistory, "persistent history feature was not advertised");
  assert(chatRegistered.features?.audioCalls, "audio call signaling feature was not advertised");
  assert(chatRegistered.features?.groupCalls, "group call signaling feature was not advertised");
  assert(chatRegistered.features?.maxGroupCallMembers === 5, "group call member limit was not advertised");
  assert(chatRegistered.features?.encryptedReels, "encrypted reels feature was not advertised");

  const reelId = crypto.randomUUID();
  const reelUpdatedPromise = once(chatWs, "story-updated");
  const reelPublishedPromise = requestAs(chatWs, {
    type: "story-publish",
    storyId: reelId,
    contentKind: "reel",
    encryptedContent: { iv: "reel-content-iv", ciphertext: "reel-content" },
    keys: [{ to: id, encryptedKey: { iv: "reel-key-iv", ciphertext: "reel-key" } }],
    profile: { displayName: "Protocol Test" }
  }, "story-publish-result");
  const [reelPublished, reelUpdated] = await Promise.all([reelPublishedPromise, reelUpdatedPromise]);
  assert(reelPublished.ok && reelPublished.storyId === reelId, "encrypted reel publish failed");
  assert(reelUpdated.story?.contentKind === "reel", "reel content kind was not preserved");
  assert(Date.parse(reelUpdated.story.expiresAt) - Date.now() > 300 * 24 * 60 * 60 * 1000, "reel retention was too short");

  let peerId = "";
  do {
    peerId = String(Math.floor(Math.random() * 900000) + 100000);
  } while (peerId === id);
  const peerKeys = await keyPair();
  const peerWs = await openRegisteredSocket(peerId, peerKeys.publicKeyJwk);

  const callId = crypto.randomUUID();
  const callRingPromise = once(peerWs, "call-signal");
  chatWs.send(JSON.stringify({
    type: "call-signal",
    to: peerId,
    callId,
    action: "ring"
  }));
  const callRing = await callRingPromise;
  assert(callRing.callId === callId && callRing.action === "ring", "instant call ring was not relayed");
  assert(callRing.from === id, "instant call ring sender was wrong");
  assert(callRing.billing?.remainingSeconds === 300, "incoming call did not show the daily free allowance");

  const callInvitePromise = once(peerWs, "call-signal");
  chatWs.send(JSON.stringify({
    type: "call-signal",
    to: peerId,
    callId,
    action: "invite",
    description: { type: "offer", sdp: "v=0\r\n" }
  }));
  const callInvite = await callInvitePromise;
  assert(callInvite.callId === callId && callInvite.action === "invite", "call invite was not relayed");
  assert(callInvite.from === id, "call invite sender was wrong");
  assert(callInvite.description?.type === "offer", "call invite offer was missing");

  const callAnswerPromise = once(chatWs, "call-signal");
  peerWs.send(JSON.stringify({
    type: "call-signal",
    to: id,
    callId,
    action: "answer",
    description: { type: "answer", sdp: "v=0\r\n" }
  }));
  const callAnswer = await callAnswerPromise;
  assert(callAnswer.callId === callId && callAnswer.action === "answer", "call answer was not relayed");
  assert(callAnswer.from === peerId, "call answer sender was wrong");
  const beforeTopUp = await requestAs(chatWs, { type: "wallet-sync" }, "wallet-sync-result");
  const peerBeforeTopUp = await requestAs(peerWs, { type: "wallet-sync" }, "wallet-sync-result");
  const topUp = await requestAs(peerWs, { type: "call-billing-top-up", callId, blocks: 1 }, "call-billing-top-up-result");
  assert(topUp.ok && topUp.billing.remainingSeconds >= 359, "either participant could not top up an active call");
  const callEndPromise = once(peerWs, "call-signal");
  chatWs.send(JSON.stringify({ type: "call-signal", to: peerId, callId, action: "end", reason: "Protocol test ended." }));
  await callEndPromise;
  await wait(100);
  const afterCall = await requestAs(chatWs, { type: "wallet-sync" }, "wallet-sync-result");
  assert(afterCall.wallet.balance === beforeTopUp.wallet.balance, "caller was charged for the other participant's refunded top-up");
  const peerAfterCall = await requestAs(peerWs, { type: "wallet-sync" }, "wallet-sync-result");
  assert(peerAfterCall.wallet.balance === peerBeforeTopUp.wallet.balance, "unused participant top-up was not refunded");

  const pricingSaved = await adminRequest("/pricing", { method: "POST", body: { pricing: { groupCallPerMinute: 37 } } });
  assert(pricingSaved.pricing.groupCallPerMinute === 37, "admin pricing update did not persist");
  const pricingRead = await adminRequest("/pricing");
  assert(pricingRead.pricing.directCallPerMinute === 12 && pricingRead.pricing.groupCallPerMinute === 37, "admin pricing read did not return authoritative values");

  const groupUpdatePromise = once(chatWs, "group-updated");
  chatWs.send(JSON.stringify({ type: "create-group", name: "Protocol Call Group", members: [peerId] }));
  const callGroup = (await groupUpdatePromise).group;
  assert(callGroup.members.includes(id) && callGroup.members.includes(peerId), "group call test group was not created");

  const groupCallId = crypto.randomUUID();
  const groupInvitePromise = once(peerWs, "group-call-invite");
  const groupStartedPromise = requestAs(chatWs, {
    type: "group-call-start",
    groupId: callGroup.id,
    callId: groupCallId
  }, "group-call-started");
  const groupStarted = await groupStartedPromise;
  const groupInvite = await groupInvitePromise;
  assert(groupStarted.ok && groupStarted.callId === groupCallId, "group call room did not start");
  assert(groupStarted.billing?.mode === "group" && groupStarted.billing.blockCost === 37, "group call did not use the admin-configured group rate");
  assert(groupInvite.groupId === callGroup.id && groupInvite.callId === groupCallId, "group call invite was not delivered");

  const peerJoinedPromise = once(chatWs, "group-call-peer-joined");
  const groupJoined = await requestAs(peerWs, {
    type: "group-call-join",
    groupId: callGroup.id,
    callId: groupCallId
  }, "group-call-joined");
  const peerJoined = await peerJoinedPromise;
  assert(groupJoined.ok && groupJoined.peers.some((peer) => peer.peerId === id), "joining member did not receive existing peers");
  assert(peerJoined.peerId === peerId, "existing member was not told who joined");

  const groupSignalPromise = once(chatWs, "call-signal");
  peerWs.send(JSON.stringify({
    type: "call-signal",
    to: id,
    callId: groupCallId,
    groupId: callGroup.id,
    action: "invite",
    description: { type: "offer", sdp: "v=0\r\n" }
  }));
  const groupSignal = await groupSignalPromise;
  assert(groupSignal.groupId === callGroup.id && groupSignal.from === peerId, "group WebRTC signal was not membership-validated and relayed");

  const peerLeftPromise = once(chatWs, "group-call-peer-left");
  peerWs.send(JSON.stringify({ type: "group-call-leave", groupId: callGroup.id, callId: groupCallId }));
  const peerLeft = await peerLeftPromise;
  assert(peerLeft.peerId === peerId, "group call leave was not broadcast");
  chatWs.send(JSON.stringify({ type: "group-call-leave", groupId: callGroup.id, callId: groupCallId }));

  const largeGroupUpdatePromise = once(chatWs, "group-updated");
  const extraMembers = [];
  for (let candidate = 700000; extraMembers.length < 5; candidate += 1) {
    const candidateId = String(candidate);
    if (candidateId !== id && candidateId !== peerId) extraMembers.push(candidateId);
  }
  chatWs.send(JSON.stringify({ type: "create-group", name: "Too Large Call Group", members: extraMembers }));
  const largeGroup = (await largeGroupUpdatePromise).group;
  const largeCallResult = await requestAs(chatWs, {
    type: "group-call-start",
    groupId: largeGroup.id,
    callId: crypto.randomUUID()
  }, "group-call-result");
  assert(largeCallResult.ok === false && /up to 5 people/i.test(largeCallResult.message), "six-person group call was not rejected clearly");

  const historyMessageId = crypto.randomUUID();
  const walletBeforeText = await requestAs(chatWs, { type: "wallet-sync" }, "wallet-sync-result");
  const sentStatusPromise = once(chatWs, "message-status");
  const deliveredHistoryMessagePromise = once(peerWs, "direct-message");
  chatWs.send(JSON.stringify({
    type: "direct-message",
    to: peerId,
    messageId: historyMessageId,
    encrypted: { iv: "receiver-iv", ciphertext: "receiver-copy" },
    senderEncrypted: { iv: "sender-iv", ciphertext: "sender-copy" },
    sentAt: "2026-01-01T00:00:00.000Z"
  }));
  const sentStatus = await sentStatusPromise;
  assert(sentStatus.messageId === historyMessageId && sentStatus.status === "sent", "online direct message was not acknowledged as sent");
  const deliveredHistoryMessage = await deliveredHistoryMessagePromise;
  assert(deliveredHistoryMessage.messageId === historyMessageId, "live message was not delivered to target");
  peerWs.send(JSON.stringify({ type: "ack-message", messageId: historyMessageId }));
  await wait(80);
  const walletAfterText = await requestAs(chatWs, { type: "wallet-sync" }, "wallet-sync-result");
  assert(walletAfterText.wallet.balance === walletBeforeText.wallet.balance, "ordinary text messages were charged");

  const attachmentMessageId = crypto.randomUUID();
  const attachmentDelivered = once(peerWs, "direct-message");
  chatWs.send(JSON.stringify({
    type: "direct-message", to: peerId, messageId: attachmentMessageId,
    encrypted: { iv: "attachment-iv", ciphertext: "attachment-copy" },
    senderEncrypted: { iv: "attachment-sender-iv", ciphertext: "attachment-sender-copy" },
    contentType: "image", attachmentBytes: 300000, sentAt: new Date().toISOString()
  }));
  await attachmentDelivered;
  await wait(80);
  const walletReserved = await requestAs(chatWs, { type: "wallet-sync" }, "wallet-sync-result");
  assert(walletReserved.wallet.balance === walletAfterText.wallet.balance - 5, "attachment size tier was not reserved");
  peerWs.send(JSON.stringify({ type: "ack-message", messageId: attachmentMessageId }));
  await wait(100);
  const walletSettled = await requestAs(chatWs, { type: "wallet-sync" }, "wallet-sync-result");
  assert(walletSettled.wallet.balance === walletReserved.wallet.balance, "delivered attachment was charged twice");
  assert(walletSettled.wallet.history.some((item) => item.messageId === attachmentMessageId && item.status === "completed"), "attachment charge did not settle after recipient save acknowledgement");
  const peerSecondDevice = await openRegisteredSocket(peerId, peerKeys.publicKeyJwk);
  const readStateSyncPromise = once(peerSecondDevice, "read-state-sync");
  peerWs.send(JSON.stringify({ type: "read-state", contactId: id, readAt: "2026-01-01T00:00:10.000Z" }));
  const readStateSync = await readStateSyncPromise;
  assert(readStateSync.contactId === id, "read state was not synchronized to another device");

  let offlinePeerId = "";
  do {
    offlinePeerId = String(Math.floor(Math.random() * 900000) + 100000);
  } while (offlinePeerId === id || offlinePeerId === peerId);
  const offlineMessageId = crypto.randomUUID();
  const queuedStatusPromise = once(chatWs, "message-status");
  const queuedNoticePromise = once(chatWs, "message-queued");
  chatWs.send(JSON.stringify({
    type: "direct-message",
    to: offlinePeerId,
    messageId: offlineMessageId,
    encrypted: { iv: "offline-iv", ciphertext: "offline-copy" },
    senderEncrypted: { iv: "offline-sender-iv", ciphertext: "offline-sender-copy" },
    sentAt: "2026-01-01T00:00:01.000Z"
  }));
  const queuedStatus = await queuedStatusPromise;
  const queuedNotice = await queuedNoticePromise;
  assert(queuedStatus.messageId === offlineMessageId && queuedStatus.status === "queued", "offline direct message was not acknowledged as queued");
  assert(queuedNotice.messageId === offlineMessageId && queuedNotice.peerId === offlinePeerId, "offline queue notice did not identify the message");
  const duplicateQueuedStatusPromise = once(chatWs, "message-status");
  chatWs.send(JSON.stringify({
    type: "direct-message",
    to: offlinePeerId,
    messageId: offlineMessageId,
    encrypted: { iv: "offline-iv", ciphertext: "offline-copy" },
    senderEncrypted: { iv: "offline-sender-iv", ciphertext: "offline-sender-copy" },
    sentAt: "2026-01-01T00:00:01.000Z"
  }));
  const duplicateQueuedStatus = await duplicateQueuedStatusPromise;
  assert(duplicateQueuedStatus.status === "queued", "duplicate retry was not acknowledged");
  const offlineKeys = await keyPair();
  const offlineWs = await openSocket();
  const queuedDeliveries = [];
  offlineWs.addEventListener("message", (event) => {
    const queued = JSON.parse(event.data);
    if (queued.type === "direct-message" && queued.messageId === offlineMessageId) queuedDeliveries.push(queued);
  });
  offlineWs.send(JSON.stringify({ type: "register", peerId: offlinePeerId, publicKeyJwk: offlineKeys.publicKeyJwk }));
  await once(offlineWs, "registered");
  await wait(150);
  assert(queuedDeliveries.length === 1, "duplicate retry created multiple offline deliveries");
  offlineWs.send(JSON.stringify({ type: "ack-message", messageId: offlineMessageId }));
  await wait(80);
  offlineWs.send(JSON.stringify({ type: "sync-offline" }));
  await wait(150);
  assert(queuedDeliveries.length === 1, "acked offline message was redelivered");
  offlineWs.close();
  await wait(120);

  const senderHistoryItemsPromise = once(chatWs, "history-items");
  const senderHistoryCompletePromise = once(chatWs, "history-sync-complete");
  chatWs.send(JSON.stringify({ type: "history-sync", limit: 50 }));
  const senderHistory = await senderHistoryItemsPromise;
  const senderHistoryItem = senderHistory.items.find((item) => item.messageId === historyMessageId);
  assert(senderHistoryItem?.historyDirection === "outbound", "sender history copy was not marked outbound");
  assert(senderHistoryItem.historyPeerId === peerId, "sender history copy did not preserve target peer");
  assert(senderHistoryItem.encrypted?.ciphertext === "sender-copy", "sender history copy did not use sender encryption");
  assert(senderHistoryItem.selfEncrypted === true, "sender history copy was not marked self-encrypted");
  const senderHistoryComplete = await senderHistoryCompletePromise;
  assert(senderHistoryComplete.count >= 1, "sender history sync count was empty");

  const receiverHistoryItemsPromise = once(peerWs, "history-items");
  const receiverHistoryCompletePromise = once(peerWs, "history-sync-complete");
  peerWs.send(JSON.stringify({ type: "history-sync", limit: 50 }));
  const receiverHistory = await receiverHistoryItemsPromise;
  const receiverHistoryItem = receiverHistory.items.find((item) => item.messageId === historyMessageId);
  assert(receiverHistoryItem?.historyDirection === "inbound", "receiver history copy was not marked inbound");
  assert(receiverHistoryItem.historyPeerId === id, "receiver history copy did not preserve sender peer");
  assert(receiverHistoryItem.encrypted?.ciphertext === "receiver-copy", "receiver history copy did not use receiver encryption");
  assert(receiverHistoryItem.readBySelf === true, "history sync did not preserve the user's read state");
  const receiverHistoryComplete = await receiverHistoryCompletePromise;
  assert(receiverHistoryComplete.count >= 1, "receiver history sync count was empty");

  const backfillMessageId = crypto.randomUUID();
  const backfillRequestId = crypto.randomUUID();
  chatWs.send(JSON.stringify({
    type: "history-backfill",
    requestId: backfillRequestId,
    entries: [{
      historyKind: "direct",
      historyDirection: "inbound",
      historyPeerId: peerId,
      from: peerId,
      messageId: backfillMessageId,
      sentAt: "2026-01-01T00:01:00.000Z",
      profile: { displayName: "Backfilled Peer" },
      peerProfile: { displayName: "Backfilled Peer" },
      peerPublicKeyJwk: peerKeys.publicKeyJwk,
      encrypted: { iv: "backfill-iv", ciphertext: "backfill-copy" }
    }]
  }));
  const backfilled = await once(chatWs, "history-backfill-result", backfillRequestId);
  assert(backfilled.ok && backfilled.stored === 1, "history backfill did not store one item");
  const backfillHistoryItemsPromise = once(chatWs, "history-items");
  const backfillHistoryCompletePromise = once(chatWs, "history-sync-complete");
  chatWs.send(JSON.stringify({ type: "history-sync", limit: 50 }));
  const backfillHistory = await backfillHistoryItemsPromise;
  const backfillHistoryItem = backfillHistory.items.find((item) => item.messageId === backfillMessageId);
  assert(backfillHistoryItem?.selfEncrypted === true, "backfilled history was not marked self-encrypted");
  assert(backfillHistoryItem.historyPeerId === peerId, "backfilled history did not preserve peer");
  assert(backfillHistoryItem.peerPublicKeyJwk, "backfilled history did not preserve peer public key");
  await backfillHistoryCompletePromise;
  chatWs.close();
  peerWs.close();
  peerSecondDevice.close();

  const bulkIds = [];
  const bulkSockets = [];
  for (let index = 0; index < 2; index += 1) {
    let bulkId = "";
    do {
      bulkId = String(Math.floor(Math.random() * 900000) + 100000);
    } while (bulkId === id || bulkIds.includes(bulkId));
    bulkIds.push(bulkId);
    const bulkKeys = await keyPair();
    const bulkWs = await openRegisteredSocket(bulkId, bulkKeys.publicKeyJwk);
    bulkSockets.push(bulkWs);
    const bulkCreated = await request(bulkWs, {
      type: "create-account",
      peerId: bulkId,
      password: "password123",
      publicKeyJwk: bulkKeys.publicKeyJwk,
      encryptedIdentityBackup: backup(`bulk-${index}`),
      encryptedRecoveryBackup: backup(`bulk-recovery-${index}`),
      recoveryPhrase: "anchor beacon cedar delta ember forest galaxy harbor island jungle lantern maple",
      profile: { displayName: `Bulk Delete ${index}`, quickAddVisible: true }
    });
    assert(bulkCreated.ok, "bulk test account creation failed");
  }
  const bulkDeleted = await adminRequest("/bulk-delete-accounts", { method: "POST", body: { peerIds: bulkIds } });
  assert(bulkDeleted.deleted.length === bulkIds.length, "admin bulk delete failed");
  const bulkStatus = await request(authWs, { type: "account-status", peerId: bulkIds[0] });
  assert(!bulkStatus.exists && !bulkStatus.hasPassword, "bulk-deleted account still exists");
  const bulkAdminSearch = await adminRequest(`/accounts?q=${bulkIds[0]}`);
  assert(!bulkAdminSearch.accounts.some((account) => account.peerId === bulkIds[0]), "bulk-deleted account still appears in admin search");
  const bulkAdminDetail = await adminRequestFailure(`/account?peerId=${bulkIds[0]}`);
  assert(bulkAdminDetail.status === 404, "bulk-deleted account detail was still readable");
  for (const bulkWs of bulkSockets) bulkWs.close();

  let supportDeleteId = "";
  do {
    supportDeleteId = String(Math.floor(Math.random() * 900000) + 100000);
  } while (supportDeleteId === id || bulkIds.includes(supportDeleteId));
  const supportDeleteKeys = await keyPair();
  const supportDeleteWs = await openRegisteredSocket(supportDeleteId, supportDeleteKeys.publicKeyJwk);
  const supportDeleteCreated = await request(supportDeleteWs, {
    type: "create-account",
    peerId: supportDeleteId,
    password: "password123",
    publicKeyJwk: supportDeleteKeys.publicKeyJwk,
    encryptedIdentityBackup: backup("support-delete"),
    encryptedRecoveryBackup: backup("support-delete-recovery"),
    recoveryPhrase: "anchor beacon cedar delta ember forest galaxy harbor island jungle lantern maple",
    profile: { displayName: "Support Delete Test", quickAddVisible: true }
  });
  assert(supportDeleteCreated.ok, "support delete test account creation failed");
  const supportDeleted = await adminRequest("/delete-account", { method: "POST", body: { peerId: supportDeleteId, confirm: supportDeleteId } });
  assert(supportDeleted.deleted.includes(supportDeleteId), "admin single delete did not report deleted account");
  const supportDeleteSearch = await adminRequest(`/accounts?q=${supportDeleteId}`);
  assert(!supportDeleteSearch.accounts.some((account) => account.peerId === supportDeleteId), "admin single-deleted account still appears in search");
  const supportDeleteStatus = await request(authWs, { type: "account-status", peerId: supportDeleteId });
  assert(!supportDeleteStatus.exists && !supportDeleteStatus.hasPassword, "admin single-deleted account still exists");
  supportDeleteWs.close();

  const deleted = await request(authWs, { type: "delete-account", peerId: id, password: "newpassword123", sessionToken: signedIn.sessionToken });
  assert(deleted.ok, "delete account failed");

  const status = await request(authWs, { type: "account-status", peerId: id });
  assert(!status.exists && !status.hasPassword, "account still exists after delete");
  ws.close();
  authWs.close();
  console.log("account protocol test passed");
} finally {
  server.kill("SIGTERM");
}

function backup(label) {
  return { version: 1, kdf: "test", salt: `${label}-salt`, iv: `${label}-iv`, data: `${label}-data` };
}

async function keyPair() {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
  return {
    publicKeyJwk: await crypto.subtle.exportKey("jwk", pair.publicKey)
  };
}

function request(ws, payload) {
  const requestId = crypto.randomUUID();
  ws.send(JSON.stringify({ ...payload, requestId }));
  const resultType = payload.type === "account-status"
    ? "account-status-result"
    : payload.type === "account-search"
    ? "account-search-results"
    : "account-response";
  return once(ws, resultType, requestId);
}

function requestAs(ws, payload, resultType) {
  const requestId = crypto.randomUUID();
  ws.send(JSON.stringify({ ...payload, requestId }));
  return once(ws, resultType, requestId);
}

async function adminRequest(path, options = {}) {
  const response = await fetch(`http://127.0.0.1:${port}/admin/api${path}`, {
    method: options.method || "GET",
    headers: {
      authorization: `Bearer ${adminToken}`,
      "content-type": "application/json"
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const payload = await response.json();
  if (!response.ok || payload.ok === false) throw new Error(payload.message || `Admin request failed: ${path}`);
  return payload;
}

async function adminRequestFailure(path, options = {}) {
  const response = await fetch(`http://127.0.0.1:${port}/admin/api${path}`, {
    method: options.method || "GET",
    headers: {
      authorization: `Bearer ${adminToken}`,
      "content-type": "application/json"
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const payload = await response.json().catch(() => ({}));
  if (response.ok && payload.ok !== false) throw new Error(`Admin request unexpectedly succeeded: ${path}`);
  return { status: response.status, payload };
}

function once(ws, type, requestId = "") {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${type}`)), 5000);
    ws.addEventListener("message", function onMessage(event) {
      const message = JSON.parse(event.data);
      if (message.type !== type || (requestId && message.requestId !== requestId)) return;
      clearTimeout(timer);
      ws.removeEventListener("message", onMessage);
      resolve(message);
    });
  });
}

async function openRegisteredSocket(peerId, publicKeyJwk) {
  const ws = await openSocket();
  ws.send(JSON.stringify({ type: "register", peerId, publicKeyJwk }));
  await once(ws, "registered");
  return ws;
}

async function openSocket() {
  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  await new Promise((resolve, reject) => {
    ws.addEventListener("open", resolve, { once: true });
    ws.addEventListener("error", reject, { once: true });
  });
  return ws;
}

function waitForServer() {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Server did not start")), 7000);
    server.stdout.on("data", (chunk) => {
      if (String(chunk).includes("listening")) {
        clearTimeout(timer);
        resolve();
      }
    });
    server.stderr.on("data", (chunk) => {
      const text = String(chunk);
      if (text.toLowerCase().includes("error")) {
        clearTimeout(timer);
        reject(new Error(text));
      }
    });
  });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
