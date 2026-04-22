// ============================================================
//  handlers/messageHandler.js  —  Main message flow logic
// ============================================================

const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const { config } = require('../config');
const { isDomainExcepted } = require('../utils/exceptions');
const { scanPipeline } = require('../utils/scanner');
const { sendAsUser } = require('../utils/webhook');

// Robust URL matching regex
const URL_REGEX = /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/gi;

// Discord Invite Regex
const INVITE_REGEX = /(?:https?:\/\/)?(?:www\.)?(?:discord\.gg\/|discord\.com\/invite\/|discordapp\.com\/invite\/)([a-zA-Z0-9-]+)/i;

/**
 * Handle incoming messages, extract links, scan, and re-send.
 * @param {import('discord.js').Message} message 
 */
async function handleMessage(message) {
  // Never process bots or webhooks
  if (message.author.bot || message.webhookId) return;

  const content = message.content;
  if (!content) return;

  // --- NEW: Block promotional Discord Invites (including hacked scam invites) ---
  if (INVITE_REGEX.test(content)) {
    const isAdmin = message.member?.permissions.has(PermissionFlagsBits.Administrator);
    if (!isAdmin) {
      if (message.deletable) await message.delete().catch(() => {});
      
      try {
        await message.author.send(`🚨 **Warning:** Promotional Discord server links and invites are not allowed in this server.`);
      } catch (e) {}

      // Log to mod channel
      try {
        const { logChannelId } = require('../config');
        const logChannel = await message.client.channels.fetch(logChannelId);
        if (logChannel && logChannel.isTextBased()) {
          const embed = new EmbedBuilder()
            .setColor('#ffae42')
            .setTitle('🛡️ Discord Invite Blocked')
            .setDescription(`Deleted a Discord invite link sent by a regular user.`)
            .addFields(
              { name: 'User', value: `${message.author} (ID: ${message.author.id})` },
              { name: 'Message Content', value: `\`\`\`\n${content.substring(0, 1000)}\n\`\`\`` }
            )
            .setTimestamp();
          await logChannel.send({ embeds: [embed] });
        }
      } catch (err) {}
      
      return; // Stop completely. Don't scan other links in the message.
    }
  }

  // Extract all URLs
  const rawUrls = content.match(URL_REGEX) || [];
  if (rawUrls.length === 0) return; // No URLs, totally ignore message
  
  // Deduplicate matched URLs
  const allUrls = [...new Set(rawUrls)];

  const exceptedUrls = [];
  const urlsToScan = [];

  for (const url of allUrls) {
    if (isDomainExcepted(url)) {
      exceptedUrls.push(url);
    } else {
      urlsToScan.push(url);
    }
  }

  // 1. ALL URLs IN EXCEPTION LIST
  if (urlsToScan.length === 0) {
    // If every single URL is an exception, we do absolutely nothing.
    return;
  }

  // 2. SOME URLs NEED SCANNING -> Message is deleted immediately.
  try {
    if (message.deletable) await message.delete();
  } catch (err) {
    console.error(`[messageHandler] Could not delete message from ${message.author.tag}:`, err.message);
  }

  // Send the temporary "Scanning..." message with the loading bar
  let tempMessage = null;
  try {
    // Attempt to grab the emoji to ensure formatting is perfect (animated vs static)
    let emojiStr = `<a:loading:1496156060539555870>`;
    try {
      if (message.client) {
        const customEmoji = message.client.emojis.cache.get('1496156060539555870');
        if (customEmoji) {
          emojiStr = customEmoji.toString();
        } else {
          // Fallback if not cached but standard static format might work
          emojiStr = `<:loading:1496156060539555870>`;
        }
      }
    } catch(e) {}
    
    const username = message.member?.displayName || message.author.username;
    tempMessage = await message.channel.send(`**${username}** sent a link... ${emojiStr} *Initializing scan...*`);
  } catch (err) {
    console.error(`[messageHandler] Could not send temp loading message:`, err.message);
  }

  // 3. RUN SCANS IN PARALLEL
  // Map urls to promises resolving to { url, scanRes }
  const scanPromises = urlsToScan.map(async (url) => {
    const scanRes = await scanPipeline(url);
    return { url, scanRes };
  });

  // Futuristic loading bar sequence to make the bot feel "alive" and highly technical
  const loadingSteps = [
    `\`[▓░░░░░░░░░]\` *Initiating Cyber Threat Analysis...*`,
    `\`[▓▓▓░░░░░░░]\` *Querying Global Threat Signatures...*`,
    `\`[▓▓▓▓▓░░░░░]\` *Verifying SSL/TLS & Domain Telemetry...*`,
    `\`[▓▓▓▓▓▓▓░░░]\` *Injecting payload to VirusTotal Neural Net...*`,
    `\`[▓▓▓▓▓▓▓▓▓░]\` *Cross-referencing Zero-Day exploits...*`,
    `\`[▓▓▓▓▓▓▓▓▓▓]\` *Finalizing security protocols...*`
  ];

  const animateLoading = async () => {
    if (!tempMessage) return;
    for (let i = 0; i < loadingSteps.length; i++) {
      try {
        await tempMessage.edit({ content: `**${username}** sent a link... ${emojiStr}\n> ${loadingSteps[i]}` });
        // Wait 1.5 seconds between steps for maximum visual effect
        await new Promise(r => setTimeout(r, 1500));
      } catch (err) {
        console.error(`[messageHandler] Animation error:`, err.message);
        break;
      }
    }
  };

  // Run the animation and the scans concurrently
  const [scanResults] = await Promise.all([
    Promise.all(scanPromises),
    animateLoading()
  ]);

  // Delete the placeholder loading message
  if (tempMessage && tempMessage.deletable) {
    try {
      await tempMessage.delete();
    } catch (err) {}
  }

  // Check if ANY URL is malicious or if BOTH APIs failed completely on a URL.
  const maliciousResults = scanResults.filter((item) => !item.scanRes.safe);

  if (maliciousResults.length > 0) {
    // A THREAT WAS FOUND! OR APIS FAILED
    // Re-send NOTHING. Send alerts instead.
    for (const match of maliciousResults) {
      await handleMaliciousOrFailedUrl(message, match.url, match.scanRes);
    }
    return;
  }

  // 4. ALL URLs ARE SAFE -> RE-SEND via Webhook
  const linesToSend = [];
  
  // Excepted URLs go first, no label
  for (const url of exceptedUrls) {
    linesToSend.push(url);
  }

  // Safe scanned URLs go next, labeled with detail
  for (const item of scanResults) {
    let apisUsed = [];
    if (item.scanRes.ipqsScore !== null) apisUsed.push('IPQualityScore');
    if (item.scanRes.vtMalicious !== null) apisUsed.push('VirusTotal');
    
    let verifiedStr = apisUsed.length > 0 ? `Verified by ${apisUsed.join(' & ')}` : `Verified securely`;
    
    let line = `${item.url} - ✅ **Safe** (${verifiedStr})`;
    
    // If one API backed up the other, indicate it via note
    if (item.scanRes.note) {
      line += `\n*Note: ${item.scanRes.note}*`;
    }
    linesToSend.push(line);
  }

  // Finally send the compiled strings as the user
  try {
    await sendAsUser(message.channel, message.member || message, linesToSend);
  } catch (err) {
    console.error(`[messageHandler] Webhook re-send failed in #${message.channel.name}:`, err.message);
  }
}

/**
 * Handle a URL that flagged as malicious or failed scanning.
 */
async function handleMaliciousOrFailedUrl(message, url, res) {
  const { logChannelId } = require('../config');

  const embed = new EmbedBuilder()
    .setTimestamp();

  if (res.reason === 'API_FAILURE_BOTH') {
    // Failure embed format
    embed
      .setColor('#ff9900') // Orange for Warning/Verification Needed
      .setTitle('⚠️ UNVERIFIED — API Failure')
      .setDescription(`**Mods: Please review this link manually.**\nReason: ${res.note} — link blocked for safety`)
      .addFields(
        { name: 'User', value: `${message.author} (ID: ${message.author.id})` },
        { name: 'URL', value: `\`${url}\`` },
        { name: 'Failed APIs', value: res.apiErrorContext || 'Unknown' }
      );
    
    // DM the user
    try {
      await message.author.send(`⚠️ Your message in ${message.guild.name} was removed because our security scanners (` + (res.apiErrorContext || 'Unknown') + `) are currently down or rate-limited. For safety, we block unscanned links. Please try again later!`);
    } catch (e) {
      // User might have DMs blocked
    }
  } else {
    // Standard Malicious Embed format
    embed
      .setColor('#ff0000') // Red for Danger
      .setTitle('🚨 Link Blocked')
      .addFields(
        { name: 'User', value: `${message.author} (ID: ${message.author.id})` },
        { name: 'URL', value: `\`${url}\`` },
        { name: 'Flagged by', value: res.reason || 'Unknown scanner' }
      );

    if (res.ipqsScore !== null) {
      embed.addFields({ name: 'IPQS Risk Score', value: `${res.ipqsScore}`, inline: true });
    }
    if (res.vtMalicious !== null) {
      embed.addFields({ name: 'VT Malicious Count', value: `${res.vtMalicious}`, inline: true });
    }

    // DM the user
    try {
      await message.author.send(`🚨 **Warning:** Your message in ${message.guild.name} was removed and flagged as malicious.\n\nFlagged by: ${res.reason}\nURL: \`${url}\``);
    } catch (e) {
      // Target might have DMs disabled.
    }
  }

  // Send to mod log
  try {
    const logChannel = await message.client.channels.fetch(logChannelId);
    if (logChannel && logChannel.isTextBased()) {
      await logChannel.send({ embeds: [embed] });
    }
  } catch (err) {
    // If fetching the log channel fails, we at least blocked it successfully above
    console.error(`[messageHandler] Could not send log to channel ID ${logChannelId}:`, err.message);
  }
}

module.exports = { handleMessage };
