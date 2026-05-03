// ============================================================
//  index.js  —  Discord Security Bot Entry Point
// ============================================================

const { Client, GatewayIntentBits, ActivityType } = require('discord.js');
const { config } = require('./config');
const { handleMessage } = require('./handlers/messageHandler');
const { handleCommand } = require('./handlers/commandHandler');

// URL regex (mirrors the one in messageHandler — used to detect edit-injected links)
const URL_REGEX = /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/gi;
const INVITE_REGEX = /(?:https?:\/\/)?(?:www\.)?(?:discord\.gg\/|discord\.com\/invite\/|discordapp\.com\/invite\/)([a-zA-Z0-9-]+)/i;

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
    { name: '👮 kavalthurai ungal nanban', type: ActivityType.Listening }
  ];

  // Note: 4000ms is the absolute fastest Discord API limit before it drops requests.
  setInterval(() => {
    const randomIndex = Math.floor(Math.random() * statuses.length);
    client.user.setActivity(statuses[randomIndex].name, { type: statuses[randomIndex].type });
  }, 4000); 
});

// Temporary AFK Map
const afkUsers = new Map();

client.on('messageCreate', async (message) => {
  if (message.author.bot || message.webhookId) return;

  // --- TEMPORARY AFK LOGIC ---
  const content = message.content.trim();

  // 1. User sets AFK
  if (content.toLowerCase().startsWith('kadala afk')) {
    const afkMsg = content.slice(10).trim() || 'AFK';
    afkUsers.set(message.author.id, { message: afkMsg, timestamp: Date.now() });
    await message.reply(`poituva nanba afk set panten ${afkMsg}`);
    return;
  }

  // 2. User comes back
  if (afkUsers.has(message.author.id)) {
    const data = afkUsers.get(message.author.id);
    const elapsed = Date.now() - data.timestamp;
    
    const seconds = Math.floor((elapsed / 1000) % 60);
    const minutes = Math.floor((elapsed / (1000 * 60)) % 60);
    const hours = Math.floor((elapsed / (1000 * 60 * 60)) % 24);
    
    let timeString = '';
    if (hours > 0) timeString += `${hours}h `;
    if (minutes > 0) timeString += `${minutes}m `;
    timeString += `${seconds}s`;
    
    afkUsers.delete(message.author.id);
    await message.reply(`Welcome back! You were gone for ${timeString.trim() || '0s'}.`);
  }

  // 3. User mentions someone who is AFK
  if (message.mentions.users.size > 0) {
    const mentionedAfkUsers = Array.from(message.mentions.users.values()).filter(u => afkUsers.has(u.id) && u.id !== message.author.id);
    
    for (const user of mentionedAfkUsers) {
      const data = afkUsers.get(user.id);
      const elapsed = Date.now() - data.timestamp;
      
      const seconds = Math.floor((elapsed / 1000) % 60);
      const minutes = Math.floor((elapsed / (1000 * 60)) % 60);
      const hours = Math.floor((elapsed / (1000 * 60 * 60)) % 24);
      
      let timeString = '';
      if (hours > 0) timeString += `${hours}h `;
      if (minutes > 0) timeString += `${minutes}m `;
      timeString += `${seconds}s`;
      
      await message.reply(`${user.username} is currently AFK: ${data.message} (${timeString.trim() || '0s'} ago)`);
    }
  }
  // --- END TEMPORARY AFK LOGIC ---

  // Try handle owner terminal commands first
  const handled = await handleCommand(message);
  
  // If it wasn't a command, funnel into standard scanning logic
  if (!handled) {
    await handleMessage(message);
  }
});

// ── EDITED MESSAGE SCANNING ──────────────────────────────────────────────────
// Catches the trick of posting plain text then editing in a malicious link.
client.on('messageUpdate', async (oldMessage, newMessage) => {
  // Ignore bot/webhook edits
  if (!newMessage || newMessage.author?.bot || newMessage.webhookId) return;

  // Fetch the full message object if it was a partial (e.g. cached before bot started)
  try {
    if (newMessage.partial) newMessage = await newMessage.fetch();
    if (oldMessage.partial) oldMessage = await oldMessage.fetch();
  } catch (err) {
    console.error('[messageUpdate] Could not fetch partial message:', err.message);
    return;
  }

  const oldContent  = oldMessage.content  || '';
  const newContent  = newMessage.content  || '';

  // Nothing changed in text? Skip.
  if (oldContent === newContent) return;

  // Check if the *edited* message now contains URLs or Discord invites
  const newUrls     = newContent.match(URL_REGEX)    || [];
  const oldUrls     = oldContent.match(URL_REGEX)    || [];
  const hasNewInvite = INVITE_REGEX.test(newContent) && !INVITE_REGEX.test(oldContent);

  // Detect any URL present in the new version that wasn't in the old version
  const brandNewUrls = newUrls.filter(u => !oldUrls.includes(u));

  if (brandNewUrls.length === 0 && !hasNewInvite) return; // No new links introduced

  console.log(`[messageUpdate] Detected ${brandNewUrls.length} new link(s) injected via edit from ${newMessage.author.tag}`);

  // Re-use the exact same scanning + deletion logic as messageCreate
  await handleMessage(newMessage);
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
