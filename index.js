// ============================================================
//  index.js  —  Discord Security Bot Entry Point
// ============================================================

const { Client, GatewayIntentBits, ActivityType } = require('discord.js');
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
  
  // Array of statuses to randomly rotate through
  const statuses = [
    { name: '🛡️ Scanning for threats', type: ActivityType.Watching },
    { name: '👀 Watching verkadala', type: ActivityType.Watching },
    { name: '🔐 Protecting users', type: ActivityType.Watching },
    { name: '🥜 Roasting Verkadala...', type: ActivityType.Playing },
    { name: '🐿️ Defending the peanuts!', type: ActivityType.Playing },
    { name: '🥜 Crackin\' down on scams', type: ActivityType.Listening },
    { name: '🛡️ Guarding the Verkadala stash', type: ActivityType.Watching },
    { name: '👨‍💻 Never Sleeping', type: ActivityType.Playing },
    { name: '👮 kavalthrai ungal nanban', type: ActivityType.Listening }
  ];

  // Note: 4000ms is the absolute fastest Discord API limit before it drops requests.
  setInterval(() => {
    const randomIndex = Math.floor(Math.random() * statuses.length);
    client.user.setActivity(statuses[randomIndex].name, { type: statuses[randomIndex].type });
  }, 4000); 
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
  console.error('[system] ERROR: Missing DISCORD_BOT_TOKEN. If hosting on Railway, please add DISCORD_BOT_TOKEN in the "Variables" tab of your Railway project dashboard.');
  process.exit(1);
}

// Log in
client.login(configData.token).catch((err) => {
  console.error('[system] Login failed:', err.message);
  process.exit(1);
});
