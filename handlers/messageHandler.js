// ============================================================
//  handlers/messageHandler.js  —  Main message flow logic
// ============================================================

const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
const { isDomainExcepted }                  = require('../utils/exceptions');
const { scanPipeline }                      = require('../utils/scanner');
const { classifyAttachment, scanFilePipeline, downloadAndHash } = require('../utils/fileScanner');
const { sendAsUser }                        = require('../utils/webhook');
const { addStrike }                         = require('../utils/timeoutManager');
const { logChannelId }                      = require('../config');

// ── Regexes ───────────────────────────────────────────────────
const URL_REGEX    = /(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})/gi;
const INVITE_REGEX = /(?:https?:\/\/)?(?:www\.)?(?:discord\.gg\/|discord\.com\/invite\/|discordapp\.com\/invite\/)([a-zA-Z0-9-]+)/i;

// ── Helpers ───────────────────────────────────────────────────
/** Fetch the mod-log channel once per message and cache the result. */
async function fetchLogChannel(client) {
  if (!logChannelId) return null;
  try {
    const ch = await client.channels.fetch(logChannelId);
    return ch?.isTextBased() ? ch : null;
  } catch { return null; }
}

/**
 * Handle incoming messages: detect invite spam, scan files and URLs.
 * @param {import('discord.js').Message} message
 */
async function handleMessage(message) {
  if (message.author.bot || message.webhookId) return;

  const content = message.content || '';

  // ── Discord invite spam block ─────────────────────────────
  if (INVITE_REGEX.test(content)) {
    const isAdmin = message.member?.permissions.has(PermissionFlagsBits.Administrator);
    if (!isAdmin) {
      if (message.deletable) await message.delete().catch(() => {});

      // ── Public channel notice (auto-deletes after 10 s) ──
      const inviteNotice = new EmbedBuilder()
        .setColor('#ffae42')
        .setTitle('🚫 Message Removed')
        .setDescription(`${message.author}, your message was removed.`)
        .addFields(
          { name: '❓ Reason', value: 'Discord server invite links are **not allowed** here.' },
        )
        .setFooter({ text: 'This notice will disappear in 10 seconds.' })
        .setTimestamp();
      message.channel.send({ embeds: [inviteNotice] })
        .then(m => setTimeout(() => m.delete().catch(() => {}), 10_000))
        .catch(() => {});

      // DM the user (best-effort)
      message.author.send('🚨 **Warning:** Promotional Discord server links and invites are not allowed in this server.').catch(() => {});

      // Strike (may auto-timeout if threshold hit)
      await addStrike(message.member);

      // Log to mod channel
      const logChannel = await fetchLogChannel(message.client);
      if (logChannel) {
        const embed = new EmbedBuilder()
          .setColor('#ffae42')
          .setTitle('🛡️ Discord Invite Blocked')
          .setDescription('Deleted a Discord invite link sent by a regular user.')
          .addFields(
            { name: 'User',            value: `${message.author} (ID: ${message.author.id})` },
            { name: 'Message Content', value: `\`\`\`\n${content.substring(0, 1000)}\n\`\`\`` },
          )
          .setTimestamp();
        logChannel.send({ embeds: [embed] }).catch(() => {});
      }
      return; // done — do not scan further
    }
  }

  // ── Classify attachments & URLs ───────────────────────────
  const allAttachments    = [...message.attachments.values()];
  const attachmentsToScan = allAttachments.filter(a => classifyAttachment(a).action === 'scan');
  const safeAttachments   = allAttachments.filter(a => classifyAttachment(a).action !== 'scan');

  const rawUrls    = content.match(URL_REGEX) || [];
  const urlsToScan = [...new Set(rawUrls)].filter(u => !isDomainExcepted(u));

  if (attachmentsToScan.length === 0 && urlsToScan.length === 0) return;

  // ── Pre-fetch all files in parallel before deleting message ─
  // (Discord CDN URLs 404 once the message is deleted)
  const preFetchedFiles = new Map();
  if (attachmentsToScan.length > 0) {
    await Promise.all(attachmentsToScan.map(async att => {
      try {
        preFetchedFiles.set(att.id, await downloadAndHash(att.url));
      } catch (e) {
        console.error(`[messageHandler] Pre-fetch failed for ${att.name}:`, e.message);
      }
    }));
  }

  // Delete the original message now that files are buffered
  if (message.deletable) await message.delete().catch(err =>
    console.error(`[messageHandler] Could not delete message from ${message.author.tag}:`, err.message)
  );

  // ── Status message ────────────────────────────────────────
  let emojiStr = '<a:loading:1496156060539555870>';
  try {
    const e = message.client.emojis.cache.get('1496156060539555870');
    if (e) emojiStr = e.toString();
  } catch {}

  const username   = message.member?.displayName || message.author.username;
  const statusLine = text => `**${username}** sent a link/file... ${emojiStr} *${text}*`;

  let tempMessage = null;
  try { tempMessage = await message.channel.send(statusLine('Initiating threat scan...')); } catch {}

  // Throttled, fire-and-forget status updater (max 1 edit per 500 ms)
  let lastUpdate = 0;
  const updateStatus = text => {
    if (!tempMessage) return;
    const now = Date.now();
    if (now - lastUpdate < 500) return;
    lastUpdate = now;
    tempMessage.edit(statusLine(text)).catch(() => {});
  };

  // ── 1. FILE SCANS (parallel) ──────────────────────────────
  const cleanFiles     = [];
  const protectedFiles = [];
  let   fileScanFailed = false;

  if (attachmentsToScan.length > 0) {
    // Fetch log channel once — reused for every clean-file embed
    const logChannel = await fetchLogChannel(message.client);

    const fileResults = await Promise.all(attachmentsToScan.map(async attachment => {
      const preFetched = preFetchedFiles.get(attachment.id);

      // Password-protected zip check
      if (preFetched && attachment.name.toLowerCase().endsWith('.zip')) {
        try {
          const AdmZip  = require('adm-zip');
          const entries = new AdmZip(preFetched.buffer).getEntries();
          if (entries.some(e => e.header && (e.header.flags & 1) !== 0)) {
            return { status: 'protected', attachment };
          }
        } catch {}
      }

      try {
        updateStatus(`Scanning file: ${attachment.name}...`);
        const scanResult = await scanFilePipeline(attachment, updateStatus, preFetched);
        return scanResult.safe
          ? { status: 'clean',     attachment }
          : { status: 'malicious', attachment, scanResult };
      } catch (err) {
        console.error(`[messageHandler] File scan error for ${attachment.name}:`, err.message);
        return { status: 'error', attachment, error: err.message };
      }
    }));

    for (const res of fileResults) {
      if (res.status === 'protected') {
        protectedFiles.push(res.attachment);

      } else if (res.status === 'malicious' || res.status === 'error') {
        fileScanFailed = true;
        if (tempMessage?.deletable) await tempMessage.delete().catch(() => {});
        const payload = res.status === 'error'
          ? { safe: false, maliciousCount: 0, method: 'error', error: res.error }
          : res.scanResult;
        await handleMaliciousFile(message, res.attachment, payload, logChannel);

      } else if (res.status === 'clean') {
        cleanFiles.push(res.attachment);
        if (logChannel) {
          const embed = new EmbedBuilder()
            .setColor('#00cc66')
            .setTitle('✅ File Scan — Clean')
            .setTimestamp()
            .addFields(
              { name: '👤 User',    value: `${message.author} (${message.author.tag})\nID: \`${message.author.id}\``, inline: true },
              { name: '📁 File',    value: `\`${res.attachment.name}\` · ${(res.attachment.size / 1024).toFixed(1)} KB`, inline: true },
              { name: '📍 Channel', value: `<#${message.channelId}>`, inline: true },
            )
            .setFooter({ text: 'File Scanner · No threats detected' });
          logChannel.send({ embeds: [embed] }).catch(() => {});
        }
      }
    }

    if (fileScanFailed) return;
  }

  // ── 2. URL SCANS (parallel) ───────────────────────────────
  if (urlsToScan.length > 0) updateStatus('Checking phishing databases...');

  const scanResults = await Promise.all(
    urlsToScan.map(async url => ({ url, scanRes: await scanPipeline(url, updateStatus) }))
  );

  if (tempMessage?.deletable) await tempMessage.delete().catch(() => {});

  const maliciousUrls = scanResults.filter(r => !r.scanRes.safe);
  if (maliciousUrls.length > 0) {
    for (const { url, scanRes } of maliciousUrls) {
      await handleMaliciousOrFailedUrl(message, url, scanRes);
    }
    return;
  }

  // ── 3. ALL SAFE — re-send ─────────────────────────────────
  const lines = [
    ...scanResults.map(r => `✅ <${r.url}> is safe!${r.scanRes.note ? ` (${r.scanRes.note})` : ''}`),
    ...cleanFiles.map(a    => `✅ File \`${a.name}\` is safe!`),
    ...protectedFiles.map(a => `⚠️ File \`${a.name}\` is password protected — download at your own risk`),
  ];

  const reattach = [...safeAttachments, ...cleanFiles, ...protectedFiles]
    .map(a => ({ attachment: a.url, name: a.name }));

  try {
    await sendAsUser(message.channel, message.member || message, lines, content, reattach);
  } catch (err) {
    console.error('[messageHandler] Webhook re-send failed:', err.message);
  }
}

// ── Malicious URL handler ─────────────────────────────────────
async function handleMaliciousOrFailedUrl(message, url, res) {
  const modEmbed = new EmbedBuilder().setTimestamp();

  if (res.reason === 'API_FAILURE_BOTH') {
    // ── Public channel notice ──
    const notice = new EmbedBuilder()
      .setColor('#ff9900')
      .setTitle('⚠️ Message Removed — Scanner Unavailable')
      .setDescription(`${message.author}, your message was removed.`)
      .addFields(
        { name: '❓ Reason', value: 'Our security scanners are temporarily unavailable. Unverified links are blocked for safety. Please try again later.' },
      )
      .setFooter({ text: 'This notice will disappear in 10 seconds.' })
      .setTimestamp();
    message.channel.send({ embeds: [notice] })
      .then(m => setTimeout(() => m.delete().catch(() => {}), 10_000))
      .catch(() => {});

    modEmbed
      .setColor('#ff9900')
      .setTitle('⚠️ UNVERIFIED — API Failure')
      .setDescription(`**Mods: Please review this link manually.**\nReason: ${res.note} — link blocked for safety`)
      .addFields(
        { name: 'User',        value: `${message.author} (ID: ${message.author.id})` },
        { name: 'URL',         value: `\`${url}\`` },
        { name: 'Failed APIs', value: res.apiErrorContext || 'Unknown' },
      );
    message.author.send(
      `⚠️ Your message in **${message.guild.name}** was removed because our security scanners (${res.apiErrorContext || 'Unknown'}) are currently down or rate-limited. Please try again later!`
    ).catch(() => {});

  } else {
    // ── Public channel notice ──
    const flaggedBy = res.reason || 'Unknown scanner';
    const notice = new EmbedBuilder()
      .setColor('#ff0000')
      .setTitle('🚨 Message Removed — Malicious Link Detected')
      .setDescription(`${message.author}, your message was removed.`)
      .addFields(
        { name: '❓ Reason',     value: `This link was flagged as **malicious** by our security scanners.` },
        { name: '🔍 Flagged by', value: flaggedBy },
      )
      .setFooter({ text: 'This notice will disappear in 10 seconds.' })
      .setTimestamp();
    message.channel.send({ embeds: [notice] })
      .then(m => setTimeout(() => m.delete().catch(() => {}), 10_000))
      .catch(() => {});

    modEmbed
      .setColor('#ff0000')
      .setTitle('🚨 Link Blocked')
      .addFields(
        { name: 'User',       value: `${message.author} (ID: ${message.author.id})` },
        { name: 'URL',        value: `\`${url}\`` },
        { name: 'Flagged by', value: flaggedBy },
      );
    if (res.ipqsScore   !== null) modEmbed.addFields({ name: 'IPQS Risk Score',    value: `${res.ipqsScore}`,   inline: true });
    if (res.vtMalicious !== null) modEmbed.addFields({ name: 'VT Malicious Count', value: `${res.vtMalicious}`, inline: true });

    message.author.send(
      `🚨 **Warning:** Your message in **${message.guild.name}** was removed and flagged as malicious.\n\nFlagged by: ${flaggedBy}\nURL: \`${url}\``
    ).catch(() => {});

    await addStrike(message.member);
  }

  const logChannel = await fetchLogChannel(message.client);
  if (logChannel) logChannel.send({ embeds: [modEmbed] }).catch(() => {});
}

// ── Malicious file handler ────────────────────────────────────
async function handleMaliciousFile(message, attachment, scanResult, logChannel) {
  const fileSizeKB = (attachment.size / 1024).toFixed(1);
  const fileExt    = (attachment.name || '').split('.').pop().toUpperCase() || 'UNKNOWN';
  const modEmbed   = new EmbedBuilder().setTimestamp();

  if (scanResult.method === 'error') {
    // ── Public channel notice ──
    const notice = new EmbedBuilder()
      .setColor('#ff9900')
      .setTitle('⚠️ Message Removed — Scanner Error')
      .setDescription(`${message.author}, your file was removed.`)
      .addFields(
        { name: '❓ Reason', value: `Our malware scanner encountered an error while checking \`${attachment.name}\`. Files are blocked when they cannot be verified. Please try again later or contact a mod.` },
      )
      .setFooter({ text: 'This notice will disappear in 10 seconds.' })
      .setTimestamp();
    message.channel.send({ embeds: [notice] })
      .then(m => setTimeout(() => m.delete().catch(() => {}), 10_000))
      .catch(() => {});

    modEmbed
      .setColor('#ff9900')
      .setTitle('⚠️ FILE UNVERIFIED — Scanner Error')
      .setDescription('File blocked for safety due to scanner failure. **Mods: please review manually.**')
      .addFields(
        { name: '👤 User',         value: `${message.author} (${message.author.tag})\nID: \`${message.author.id}\``, inline: true },
        { name: '📁 File',         value: `\`${attachment.name}\`\n${fileSizeKB} KB · \`${fileExt}\``, inline: true },
        { name: '🔗 Original URL', value: `[View File](${attachment.url})` },
        { name: '❌ Error',         value: `\`\`\`${scanResult.error || 'Unknown error'}\`\`\`` },
        { name: '📍 Channel',      value: `<#${message.channelId}>`, inline: true },
        { name: '🕐 Time',         value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
      )
      .setFooter({ text: 'File Scanner · Error' });
    message.author.send(
      `⚠️ Your file **${attachment.name}** in **${message.guild.name}** was removed because our malware scanner encountered an error. Please try again later or contact a mod.`
    ).catch(() => {});

  } else {
    const threatLabel = scanResult.popularThreatName
      ? `**${scanResult.popularThreatName}**`
      : `Unknown (${scanResult.maliciousCount} engine${scanResult.maliciousCount !== 1 ? 's' : ''} flagged)`;
    const threatNames = scanResult.threatNames?.length ? scanResult.threatNames.map(n => `\`${n}\``).join('\n') : '`N/A`';
    const threatTypes = scanResult.threatTypes?.length ? scanResult.threatTypes.map(t => `\`${t}\``).join(', ') : '`N/A`';

    // ── Public channel notice ──
    const notice = new EmbedBuilder()
      .setColor('#ff0000')
      .setTitle('🚨 Message Removed — Malicious File Detected')
      .setDescription(`${message.author}, your file was removed.`)
      .addFields(
        { name: '❓ Reason',              value: `\`${attachment.name}\` was flagged as **malicious** by our security scanners.` },
        { name: '🦠 Threat',             value: threatLabel },
        { name: '📊 Engines that flagged', value: `${scanResult.maliciousCount} AV engine(s)` },
      )
      .setFooter({ text: 'This notice will disappear in 10 seconds.' })
      .setTimestamp();
    message.channel.send({ embeds: [notice] })
      .then(m => setTimeout(() => m.delete().catch(() => {}), 10_000))
      .catch(() => {});

    modEmbed
      .setColor('#ff0000')
      .setTitle('🚨 MALICIOUS FILE BLOCKED')
      .setDescription(`A file uploaded by ${message.author} has been flagged as **malicious** and blocked.`)
      .addFields(
        { name: '👤 User',                  value: `${message.author} (${message.author.tag})\nID: \`${message.author.id}\``, inline: true },
        { name: '📁 File',                  value: `\`${attachment.name}\`\n${fileSizeKB} KB · \`${fileExt}\``, inline: true },
        { name: '\u200b',                   value: '\u200b', inline: true },
        { name: '🦠 Threat Classification', value: threatLabel, inline: true },
        { name: '🔬 Scan Method',           value: scanResult.method === 'hash-lookup' ? '`Hash Reputation`' : '`Full VT Sandbox`', inline: true },
        { name: '\u200b',                   value: '\u200b', inline: true },
        { name: '📊 Engine Results',        value: [`🔴 Malicious: **${scanResult.maliciousCount}**`, `🟠 Suspicious: **${scanResult.suspiciousCount || 0}**`, `🟢 Harmless: **${scanResult.harmlessCount || 0}**`, `⚪ Undetected: **${scanResult.undetectedCount || 0}**`].join('\n'), inline: true },
        { name: '🏷️ Threat Names Detected', value: threatNames, inline: true },
        { name: '⚙️ Exploit Types',         value: threatTypes, inline: false },
        { name: '🔗 Original File URL',     value: `[View on Discord CDN](${attachment.url})` },
        { name: '📍 Channel',               value: `<#${message.channelId}>`, inline: true },
        { name: '🕐 Detected At',           value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
      )
      .setFooter({ text: 'File Scanner · Powered by VirusTotal' });

    message.author.send(
      `🚨 **Malware Detected:** Your file \`${attachment.name}\` in **${message.guild.name}** was flagged as malicious by **${scanResult.maliciousCount}** AV engine(s) and removed.\n\nThreat: ${scanResult.popularThreatName || 'Unknown'}`
    ).catch(() => {});

    await addStrike(message.member);
  }

  const ch = logChannel || await fetchLogChannel(message.client);
  if (ch) ch.send({ embeds: [modEmbed] }).catch(() => {});
}

module.exports = { handleMessage };
