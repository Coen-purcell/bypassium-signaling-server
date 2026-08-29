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
    console.log(`Support bot skipped. Missing: ${missingBotConfig().join(", ")}.`);
    return;
  }

  const bot = spawnNode("support-bot", ["support-bot.js"], {
    BYPASSIUM_SERVER_URL: localServerUrl,
    BOT_DISABLE_HEALTH_SERVER: "true"
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
  return missingBotConfig().length === 0;
}

function missingBotConfig() {
  const provider = String(process.env.AI_PROVIDER || "groq").toLowerCase();
  const missing = [];
  if (!process.env.BOT_PEER_ID) missing.push("BOT_PEER_ID");
  if (!process.env.BOT_PASSWORD) missing.push("BOT_PASSWORD");
  if (provider === "openai" && !process.env.OPENAI_API_KEY) missing.push("OPENAI_API_KEY");
  if (provider !== "openai" && !process.env.GROQ_API_KEY) missing.push("GROQ_API_KEY");
  return missing;
}

async function waitForServerReady() {
  const deadline = Date.now() + 15000;
  while (!shuttingDown && Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  console.warn("Main server readiness wait expired; the Support bot will use its own reconnect loop.");
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
void waitForServerReady().then(startBot);
