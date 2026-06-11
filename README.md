# Bypassium Signaling Server

Tiny WebSocket signaling server for Bypassium Messenger.

It only exchanges temporary WebRTC setup data. It does not store messages, contacts, profiles, or chat history.

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
- Free plan is fine for testing, but it may sleep when inactive.
