# Bypassium Message Server

WebSocket relay and temporary offline inbox for Bypassium Messenger.

The server:

- Relays encrypted direct and group message envelopes.
- Temporarily stores undelivered encrypted envelopes in Redis or Upstash.
- Deletes queued envelopes only after the receiving extension acknowledges local storage.
- Relays Sent, Delivered, and Read status updates.
- Stores public profiles, public encryption keys, group membership, ownership, and group roles.
- Never receives plaintext message bodies.
- Keeps B-Coin balances, transfers, attachment charges, call reservations, refunds, and Arcade rewards authoritative on the server.

## Admin pricing

Open `/admin`, unlock it with `ADMIN_TOKEN`, then use **B-Coin pricing** to change attachment tiers, direct and group call rates, the daily direct-call allowance, Deck Flip cost, and every Memory Flip reward tier. Pricing is persisted in Redis/Upstash and broadcast to connected clients immediately.

Defaults are 12 B-Coins per direct-call minute and 32 B-Coins per group-call minute. Group-call starters fund the first minute; any participant can top up, and unused paid time is refunded in five-second increments.

This package can also run the Bypassium Support bot in the same Render service. When `npm start` runs, `start-all.js` starts the main server first, then starts `support-bot.js` against the local server URL. That means if Render wakes the main server, the Support bot wakes with it too.

## Local Run

```powershell
npm install
npm start
```

Health check:

```text
http://localhost:10000/health
```

## Render

Create a **Web Service** from this repo.

- Build command: `npm install`
- Start command: `npm start`
- Health check path: `/health`
- Configure `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` for persistent offline delivery.

To enable the Support bot in this same service, add these environment variables to the same Render service:

```env
BOT_PEER_ID=767838
BOT_PASSWORD=the-support-account-password
AI_PROVIDER=groq
GROQ_API_KEY=your-groq-api-key
GROQ_MODEL=llama-3.1-8b-instant
BOT_DIRECT_REPLY_MODE=all
BOT_GROUP_REPLY_MODE=mention
BOT_HUMAN_OPERATOR_IDS=907623,137096,396172
BOT_OWNER_IDS=904674,907623,137096,396172
BYPASSIUM_ADMIN_TOKEN=the-admin-token-from-this-server
BYPASSIUM_ADMIN_BASE_URL=https://bypassium-signaling-server.onrender.com
BOT_PUBLISH_PROFILE=false
```

Do not add `BYPASSIUM_SERVER_URL` for the same-service bot. The launcher forces it to `ws://127.0.0.1:$PORT` so the bot talks to the server inside the same Render instance.
