import { spawn } from "node:child_process";

const port = String(process.env.PORT || "10000");
const localServerUrl = `ws://127.0.0.1:${port}`;
let shuttingDown = false;
let botRestartDelayMs = 1000;
const children = new Map();

function startServer() {
  const server = spawnNode("server", ["server.js"]);
  server.on("exit", (code, signal) => {
    children.delete("server");
    if (shuttingDown) return;
    console.error(`Bypassium server stopped (${formatExit(code, signal)}). Stopping service.`);
    shutdown(code || 1);
  });
}

function startBot() {
  if (!botIsConfigured()) {
    console.log("Support bot skipped. Add BOT_PASSWORD and an AI API key to enable it in this service.");
    return;
  }

  const bot = spawnNode("support-bot", ["support-bot.js"], {
    BYPASSIUM_SERVER_URL: localServerUrl,
    PORT: "0"
  });

  bot.on("exit", (code, signal) => {
    children.delete("support-bot");
    if (shuttingDown) return;
    console.error(`Support bot stopped (${formatExit(code, signal)}). Restarting soon.`);
    const delay = botRestartDelayMs;
    botRestartDelayMs = Math.min(30000, Math.round(botRestartDelayMs * 1.6));
    setTimeout(startBot, delay);
  });
}

function spawnNode(name, args, extraEnv = {}) {
  console.log(`Starting ${name}...`);
  const child = spawn(process.execPath, args, {
    stdio: ["ignore", "inherit", "inherit"],
    env: { ...process.env, ...extraEnv }
  });
  children.set(name, child);
  return child;
}

function botIsConfigured() {
  const provider = String(process.env.AI_PROVIDER || "groq").toLowerCase();
  const hasAiKey = provider === "openai"
    ? Boolean(process.env.OPENAI_API_KEY)
    : Boolean(process.env.GROQ_API_KEY);
  return Boolean(process.env.BOT_PEER_ID && process.env.BOT_PASSWORD && hasAiKey);
}

function shutdown(code = 0) {
  shuttingDown = true;
  for (const child of children.values()) child.kill("SIGTERM");
  setTimeout(() => process.exit(code), 1500).unref();
}

function formatExit(code, signal) {
  if (signal) return `signal ${signal}`;
  return `exit ${code ?? "unknown"}`;
}

process.on("SIGTERM", () => shutdown(0));
process.on("SIGINT", () => shutdown(0));

startServer();
setTimeout(startBot, 1500);
