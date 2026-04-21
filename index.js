// ============================================================
//  index.js  —  Discord Security Bot Entry Point
// ============================================================

const { Client, GatewayIntentBits } = require('discord.js');
const { config } = require('./config');
const { handleMessage } = require('./handlers/messageHandler');
const { handleCommand } = require('./handlers/commandHandler');

// Require module exports from config directly where needed to prevent circular dependencies
const configData = require('./config');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent, // CRITICAL: Requires 'Message Content Intent' enabled on Developer Portal
    GatewayIntentBits.GuildWebhooks,
  ],
});

client.once('ready', () => {
  console.log(`[system] Discord Security Bot is online! Logged in as ${client.user.tag}`);
});

client.on('messageCreate', async (message) => {
  // Try handle owner terminal commands first
  const handled = await handleCommand(message);
  
  // If it wasn't a command, funnel into standard scanning logic
  if (!handled) {
    await handleMessage(message);
  }
});

// Avoid crashes on unhandled rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('[Unhandled Rejection]', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('[Uncaught Exception]', err.message, err.stack);
});

if (!configData.token || configData.token === 'YOUR_BOT_TOKEN') {
  console.error('[system] ERROR: You must replace "YOUR_BOT_TOKEN" in config.js with your actual bot token.');
  process.exit(1);
}

// Log in
client.login(configData.token).catch((err) => {
  console.error('[system] Login failed:', err.message);
  process.exit(1);
});
