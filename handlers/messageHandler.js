// ============================================================
//  handlers/messageHandler.js  —  Main message flow logic
// ============================================================

const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const { config } = require('../config');
const { isDomainExcepted } = require('../utils/exceptions');
const { scanPipeline } = require('../utils/scanner');
const { classifyAttachment, scanFilePipeline, downloadAndHash } = require('../utils/fileScanner');
const { sendAsUser } = require('../utils/webhook');
const { addStrike } = require('../utils/timeoutManager');

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

  const content = message.content || "";

  // --- NEW: Block promotional Discord Invites (including hacked scam invites) ---
  if (INVITE_REGEX.test(content)) {
    const isAdmin = message.member?.permissions.has(PermissionFlagsBits.Administrator);
    if (!isAdmin) {
      if (message.deletable) await message.delete().catch(() => {});
      
      try {
        await message.author.send(`🚨 **Warning:** Promotional Discord server links and invites are not allowed in this server.`);
      } catch (e) {}
      
      const { addStrike } = require('../utils/timeoutManager');
      await addStrike(message.member);

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
  const allAttachments = [...message.attachments.values()];
  const attachmentsToScan = allAttachments.filter(a => classifyAttachment(a).action === 'scan');
  const safeAttachments = allAttachments.filter(a => classifyAttachment(a).action === 'ignore');

  // Extract text URLs
  const rawUrls = content.match(URL_REGEX) || [];
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

  if (attachmentsToScan.length === 0 && urlsToScan.length === 0) {
    // Nothing to scan (either empty or everything is safe/excepted)
    return;
  }

  // PRE-FETCH FILES BEFORE DELETING MESSAGE (Prevents Discord CDN 404 errors)
  const preFetchedFiles = new Map();
  if (attachmentsToScan.length > 0) {
    for (const att of attachmentsToScan) {
      try {
        const data = await downloadAndHash(att.url);
        preFetchedFiles.set(att.id, data);
      } catch (e) {
        console.error(`[messageHandler] Pre-fetch failed for ${att.name}:`, e.message);
      }
    }
  }

  // WE NEED TO SCAN SOMETHING -> Delete immediately now that files are buffered
  try {
    if (message.deletable) await message.delete();
  } catch (err) {
    console.error(`[messageHandler] Could not delete message from ${message.author.tag}:`, err.message);
  }

  let emojiStr = `<a:loading:1496156060539555870>`;
  try {
    if (message.client) {
      const customEmoji = message.client.emojis.cache.get('1496156060539555870');
      if (customEmoji) emojiStr = customEmoji.toString();
    }
  } catch(e) {}

  const username = message.member?.displayName || message.author.username;
  const statusLine = (text) => `**${username}** sent a link/file... ${emojiStr} *${text}*`;

  let tempMessage = null;
  try {
    tempMessage = await message.channel.send(statusLine('Initiating threat scan...'));
  } catch (err) {}

  // Fire-and-forget status updates. Awaiting these causes Discord edit rate limits to severely choke the scanning speed.
  let lastUpdate = 0;
  const updateStatus = (text) => {
    if (!tempMessage) return;
    const now = Date.now();
    // Discord heavily rate limits message edits (max 5 per 5s).
    // Throttle local updates to roughly 1 per 500ms to prevent 429 explosions, and never block the main thread.
    if (now - lastUpdate < 500) return; 
    lastUpdate = now;
    tempMessage.edit(statusLine(text)).catch(() => {});
  };

  // 1. RUN FILE SCANS
  const cleanFiles = [];
  const protectedFiles = [];
  let fileScanFailed = false;

  if (attachmentsToScan.length > 0) {
    const filePromises = attachmentsToScan.map(async (attachment) => {
      // Check if it's a password-protected zip file
      let isProtectedZip = false;
      const preFetched = preFetchedFiles.get(attachment.id);

      if (preFetched && attachment.name.toLowerCase().endsWith('.zip')) {
        try {
          const AdmZip = require('adm-zip');
          const zip = new AdmZip(preFetched.buffer);
          const entries = zip.getEntries();
          isProtectedZip = entries.some(e => e.header && (e.header.flags & 1) !== 0);
        } catch (e) {
          // Not a valid zip or corrupted
        }
      }

      if (isProtectedZip) {
        return { status: 'protected', attachment };
      }

      try {
        updateStatus(`Scanning file: ${attachment.name}...`);
        const scanResult = await scanFilePipeline(attachment, updateStatus, preFetched);
        if (!scanResult.safe) return { status: 'malicious', attachment, scanResult };
        
        return { status: 'clean', attachment };
      } catch (err) {
        console.error(`[messageHandler] File scan error for ${attachment.name}:`, err.message);
        return { status: 'error', attachment, error: err.message };
      }
    });

    const fileResults = await Promise.all(filePromises);

    for (const res of fileResults) {
      if (res.status === 'protected') {
        protectedFiles.push(res.attachment);
      } else if (res.status === 'malicious' || res.status === 'error') {
        fileScanFailed = true;
        if (tempMessage?.deletable) await tempMessage.delete().catch(() => {});
        
        const payload = res.status === 'error' 
           ? { safe: false, maliciousCount: 0, method: 'error', error: res.error } 
           : res.scanResult;
           
        await handleMaliciousFile(message, res.attachment, payload);
      } else if (res.status === 'clean') {
        cleanFiles.push(res.attachment);
        
        // Log clean file scan to mod log
        try {
          const { logChannelId } = require('../config');
          const logChannel = await message.client.channels.fetch(logChannelId);
          if (logChannel?.isTextBased()) {
            const { EmbedBuilder } = require('discord.js');
            const cleanEmbed = new EmbedBuilder()
              .setColor('#00cc66')
              .setTitle('✅ File Scan — Clean')
              .setTimestamp()
              .addFields(
                { name: '👤 User', value: `${message.author} (${message.author.tag})\nID: \`${message.author.id}\``, inline: true },
                { name: '📁 File', value: `\`${res.attachment.name}\` · ${(res.attachment.size/1024).toFixed(1)} KB`, inline: true },
                { name: '📍 Channel', value: `<#${message.channelId}>`, inline: true },
              )
              .setFooter({ text: 'File Scanner · No threats detected' });
            await logChannel.send({ embeds: [cleanEmbed] });
          }
        } catch(err) {}
      }
    }
    
    // Stop processing entirely if any file was flagged as a threat
    if (fileScanFailed) return;
  }

  // 2. RUN URL SCANS
  if (urlsToScan.length > 0) {
    await updateStatus('Checking phishing databases...');
  }
  const scanPromises = urlsToScan.map(async (url) => {
    const scanRes = await scanPipeline(url, updateStatus);
    return { url, scanRes };
  });

  const scanResults = await Promise.all(scanPromises);

  // Clean up status message
  if (tempMessage && tempMessage.deletable) {
    try { await tempMessage.delete(); } catch(e) {}
  }

  const maliciousResults = scanResults.filter((item) => !item.scanRes.safe);
  if (maliciousResults.length > 0) {
    // URL scan failed! Alert mods.
    for (const match of maliciousResults) {
      await handleMaliciousOrFailedUrl(message, match.url, match.scanRes);
    }
    return;
  }

  // 3. ALL SAFE -> RE-SEND ALL IN ONE MESSAGE
  const linesToSend = [];
  
  for (const item of scanResults) {
    let line = `✅ <${item.url}> is safe!`;
    if (item.scanRes.note) {
      line += ` (${item.scanRes.note})`;
    }
    linesToSend.push(line);
  }

  for (const attachment of cleanFiles) {
    linesToSend.push(`✅ File \`${attachment.name}\` is safe!`);
  }

  for (const attachment of protectedFiles) {
    linesToSend.push(`⚠️ File \`${attachment.name}\` is password protected and downloading is at users own risk`);
  }

  const allReattachFiles = [...safeAttachments, ...cleanFiles, ...protectedFiles].map(a => ({ attachment: a.url, name: a.name }));

  try {
    await sendAsUser(message.channel, message.member || message, linesToSend, content, allReattachFiles);
  } catch (err) {
    console.error(`[messageHandler] Webhook re-send failed:`, err.message);
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
      
      const { addStrike } = require('../utils/timeoutManager');
      await addStrike(message.member);
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
      
      const { addStrike } = require('../utils/timeoutManager');
      await addStrike(message.member);
    }

  try {
    const logChannel = await message.client.channels.fetch(logChannelId);
    if (logChannel?.isTextBased()) await logChannel.send({ embeds: [embed] });
  } catch(err) {
    console.error(`[messageHandler] Could not log malicious file:`, err.message);
  }
}

module.exports = { handleMessage };
