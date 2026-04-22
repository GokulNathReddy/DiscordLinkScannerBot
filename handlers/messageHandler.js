// ============================================================
//  handlers/messageHandler.js  —  Main message flow logic
// ============================================================

const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const { config } = require('../config');
const { isDomainExcepted } = require('../utils/exceptions');
const { scanPipeline } = require('../utils/scanner');
const { classifyAttachment, scanFilePipeline } = require('../utils/fileScanner');
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

  // ── ATTACHMENT SCANNING ──────────────────────────────────────
  const attachments = [...message.attachments.values()];
  const attachmentsToScan = attachments.filter(a => classifyAttachment(a).action === 'scan');

  if (attachmentsToScan.length > 0) {
    // Delete the original message immediately
    try {
      if (message.deletable) await message.delete();
    } catch (err) {}

    const username = message.member?.displayName || message.author.username;
    let emojiStr = `<a:loading:1496156060539555870>`;
    try {
      const customEmoji = message.client.emojis.cache.get('1496156060539555870');
      if (customEmoji) emojiStr = customEmoji.toString();
    } catch(e) {}

    const statusLine = (text) => `**${username}** sent a file... ${emojiStr} *${text}*`;
    let fileTempMsg = null;

    try {
      fileTempMsg = await message.channel.send(statusLine('Initiating malware scan...'));
    } catch(e) {}

    const updateFileStatus = async (text) => {
      if (!fileTempMsg) return;
      try { await fileTempMsg.edit(statusLine(text)); } catch(e) {}
    };

    for (const attachment of attachmentsToScan) {
      let scanResult;
      try {
        scanResult = await scanFilePipeline(attachment, updateFileStatus);
      } catch (err) {
        console.error(`[messageHandler] File scan error for ${attachment.name}:`, err.message);
        // API failure — block and alert mods
        await handleMaliciousFile(message, attachment, { 
          safe: false, 
          maliciousCount: 0, 
          method: 'error',
          error: err.message 
        });
        if (fileTempMsg?.deletable) await fileTempMsg.delete().catch(() => {});
        return;
      }

      if (!scanResult.safe) {
        if (fileTempMsg?.deletable) await fileTempMsg.delete().catch(() => {});
        await handleMaliciousFile(message, attachment, scanResult);
        return;
      }
    }

    // All files clean — delete status msg and re-send via webhook
    if (fileTempMsg?.deletable) await fileTempMsg.delete().catch(() => {});

    try {
      const webhookContent = content || null;
      const { getOrCreateWebhook } = require('../utils/webhook');
      const webhook = await getOrCreateWebhook(message.channel);
      if (webhook) {
        const member = message.member || message.author;
        await webhook.send({
          content: webhookContent ? `${webhookContent}\n✅ File scanned — clean` : '✅ File scanned — clean',
          username: member.displayName || message.author.username,
          avatarURL: message.author.displayAvatarURL(),
          files: attachmentsToScan.map(a => ({ attachment: a.url, name: a.name })),
        });
      }
    } catch (err) {
      console.error('[messageHandler] Failed to re-send clean file:', err.message);
    }

    // Log clean scan to mod log
    try {
      const { logChannelId } = require('../config');
      const logChannel = await message.client.channels.fetch(logChannelId);
      if (logChannel?.isTextBased()) {
        const cleanEmbed = new EmbedBuilder()
          .setColor('#00cc66')
          .setTitle('✅ File Scan — Clean')
          .setTimestamp()
          .addFields(
            { name: '👤 User', value: `${message.author} (${message.author.tag})\nID: \`${message.author.id}\``, inline: true },
            { name: '📁 File(s)', value: attachmentsToScan.map(a => {
                const ext = (a.name || '').split('.').pop().toUpperCase() || 'UNKNOWN';
                return `\`${a.name}\` · ${(a.size/1024).toFixed(1)} KB · \`${ext}\``;
              }).join('\n'), inline: true },
            { name: '📍 Channel', value: `<#${message.channelId}>`, inline: true },
            { name: '🕐 Scanned At', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
          )
          .setFooter({ text: 'File Scanner · No threats detected' });
        await logChannel.send({ embeds: [cleanEmbed] });
      }
    } catch(err) {}

    // If there are also URLs in this message, fall through and scan them too
    const rawUrlsCheck = content.match(URL_REGEX) || [];
    if (rawUrlsCheck.length === 0) return;
  }
  // ── END ATTACHMENT SCANNING ───────────────────────────────────

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

  // Resolve loading emoji
  let emojiStr = `<a:loading:1496156060539555870>`;
  try {
    if (message.client) {
      const customEmoji = message.client.emojis.cache.get('1496156060539555870');
      if (customEmoji) emojiStr = customEmoji.toString();
    }
  } catch(e) {}

  const username = message.member?.displayName || message.author.username;

  // Helper to build a status line
  const statusLine = (text) => `**${username}** sent a link... ${emojiStr} *${text}*`;

  // Send the initial loading message
  let tempMessage = null;
  try {
    tempMessage = await message.channel.send(statusLine('Initiating threat scan...'));
  } catch (err) {
    console.error(`[messageHandler] Could not send temp loading message:`, err.message);
  }

  // Helper to silently edit the status message
  const updateStatus = async (text) => {
    if (!tempMessage) return;
    try { await tempMessage.edit(statusLine(text)); } catch(e) {}
  };

  // 3. RUN SCANS — step-by-step with live status updates
  await updateStatus('Checking phishing databases...');

  const scanPromises = urlsToScan.map(async (url) => {
    const scanRes = await scanPipeline(url, updateStatus);
    return { url, scanRes };
  });

  const scanResults = await Promise.all(scanPromises);

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

  // Safe scanned URLs go next, labeled "✅ Safe"
  for (const item of scanResults) {
    let line = `${item.url} ✅ Safe`;
    // If one API backed up the other, indicate it via note
    if (item.scanRes.note) {
      line += ` (${item.scanRes.note})`;
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

/**
 * Handle a file that was flagged as malicious or failed scanning.
 */
async function handleMaliciousFile(message, attachment, scanResult) {
  const { logChannelId } = require('../config');
  const fileSizeKB = (attachment.size / 1024).toFixed(1);
  const fileExt = (attachment.name || '').split('.').pop().toUpperCase() || 'UNKNOWN';
  const embed = new EmbedBuilder().setTimestamp();

  if (scanResult.method === 'error') {
    // ── Scanner error embed ──────────────────────────────────
    embed
      .setColor('#ff9900')
      .setTitle('⚠️ FILE UNVERIFIED — Scanner Error')
      .setDescription(`File blocked for safety due to scanner failure. **Mods: please review manually.**`)
      .addFields(
        { name: '👤 User', value: `${message.author} (${message.author.tag})\nID: \`${message.author.id}\``, inline: true },
        { name: '📁 File', value: `\`${attachment.name}\`\n${fileSizeKB} KB · \`${fileExt}\``, inline: true },
        { name: '🔗 Original URL', value: `[View File](${attachment.url})` },
        { name: '❌ Error', value: `\`\`\`${scanResult.error || 'Unknown error'}\`\`\`` },
        { name: '📍 Channel', value: `<#${message.channelId}>`, inline: true },
        { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
      )
      .setFooter({ text: 'File Scanner · Error' });

    try {
      await message.author.send(`⚠️ Your file **${attachment.name}** in **${message.guild.name}** was removed because our malware scanner encountered an error. Please try again later or contact a mod.`);
    } catch(e) {}

  } else {
    // ── Malicious file embed ─────────────────────────────────
    const threatLabel = scanResult.popularThreatName
      ? `**${scanResult.popularThreatName}**`
      : `Unknown (${scanResult.maliciousCount} engine${scanResult.maliciousCount !== 1 ? 's' : ''} flagged)`;

    const threatNamesStr = scanResult.threatNames?.length
      ? scanResult.threatNames.map(n => `\`${n}\``).join('\n')
      : '`N/A`';

    const threatTypesStr = scanResult.threatTypes?.length
      ? scanResult.threatTypes.map(t => `\`${t}\``).join(', ')
      : '`N/A`';

    embed
      .setColor('#ff0000')
      .setTitle('🚨 MALICIOUS FILE BLOCKED')
      .setDescription(`A file uploaded by ${message.author} has been flagged as **malicious** and blocked.`)
      .addFields(
        { name: '👤 User', value: `${message.author} (${message.author.tag})\nID: \`${message.author.id}\``, inline: true },
        { name: '📁 File', value: `\`${attachment.name}\`\n${fileSizeKB} KB · \`${fileExt}\``, inline: true },
        { name: '\u200b', value: '\u200b', inline: true }, // spacer
        { name: '🦠 Threat Classification', value: threatLabel, inline: true },
        { name: '🔬 Scan Method', value: scanResult.method === 'hash-lookup' ? '`Hash Reputation`' : '`Full VT Sandbox`', inline: true },
        { name: '\u200b', value: '\u200b', inline: true },
        { name: '📊 Engine Results', value: [
            `🔴 Malicious: **${scanResult.maliciousCount}**`,
            `🟠 Suspicious: **${scanResult.suspiciousCount || 0}**`,
            `🟢 Harmless: **${scanResult.harmlessCount || 0}**`,
            `⚪ Undetected: **${scanResult.undetectedCount || 0}**`,
          ].join('\n'), inline: true },
        { name: '🏷️ Threat Names Detected', value: threatNamesStr, inline: true },
        { name: '⚙️ Exploit Types', value: threatTypesStr, inline: false },
        { name: '🔗 Original File URL', value: `[View on Discord CDN](${attachment.url})` },
        { name: '📍 Channel', value: `<#${message.channelId}>`, inline: true },
        { name: '🕐 Detected At', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
      )
      .setFooter({ text: 'File Scanner · Powered by VirusTotal' });

    try {
      await message.author.send(`🚨 **Malware Detected:** Your file \`${attachment.name}\` in **${message.guild.name}** was flagged as malicious by **${scanResult.maliciousCount}** AV engine(s) and removed.\n\nThreat: ${scanResult.popularThreatName || 'Unknown'}`);
    } catch(e) {}
  }

  try {
    const logChannel = await message.client.channels.fetch(logChannelId);
    if (logChannel?.isTextBased()) await logChannel.send({ embeds: [embed] });
  } catch(err) {
    console.error(`[messageHandler] Could not log malicious file:`, err.message);
  }
}

module.exports = { handleMessage };
