// ============================================================
//  utils/webhook.js  —  Per-channel webhook management
//  Fetches or creates a bot-owned webhook and sends messages
//  impersonating the original sender's username + avatar.
// ============================================================

const { WebhookClient } = require('discord.js');

/** In-memory cache: channelId → WebhookClient */
const webhookClientCache = new Map();

/**
 * Fetch the first bot-owned webhook for a channel, or create one.
 * Caches the result in-memory for subsequent uses.
 *
 * @param {import('discord.js').TextChannel} channel
 * @returns {Promise<WebhookClient>}
 */
async function getOrCreateWebhook(channel) {
  if (webhookClientCache.has(channel.id)) {
    return webhookClientCache.get(channel.id);
  }

  let webhook = null;

  try {
    // Look for an existing webhook this bot owns
    const webhooks = await channel.fetchWebhooks();
    webhook = webhooks.find((wh) => wh.owner?.id === channel.client.user.id) ?? null;
  } catch (err) {
    console.error(`[webhook] Could not fetch webhooks for #${channel.name}:`, err.message);
  }

  if (!webhook) {
    try {
      webhook = await channel.createWebhook({
        name: 'Link Scanner',
        reason: 'Auto-created by Discord Security Bot for link re-sending',
      });
      console.log(`[webhook] Created new webhook in #${channel.name}`);
    } catch (err) {
      throw new Error(`Failed to create webhook in #${channel.name}: ${err.message}`);
    }
  }

  const client = new WebhookClient({ id: webhook.id, token: webhook.token });
  webhookClientCache.set(channel.id, client);
  return client;
}

/**
 * Send URL lines as the original sender via webhook impersonation.
 *
 * @param {import('discord.js').TextChannel} channel
 * @param {import('discord.js').GuildMember} member  - The original message author
 * @param {string[]} lines  - Each string is one URL line (with optional label)
 * @param {string} originalContent - The original message text
 * @param {Array} files - Array of objects with file URLs / names to re-attach
 * @returns {Promise<void>}
 */
async function sendAsUser(channel, member, lines, originalContent = '', files = []) {
  const webhookClient = await getOrCreateWebhook(channel);

  // Combine original content and the scan summaries
  let finalContent = originalContent;
  if (lines && lines.length > 0) {
    finalContent += `\n\n🛡️ **Verified Safe:**\n${lines.join('\n')}`;
  }

  const username  = member.displayName || member.user.username;
  const avatarURL = member.user.displayAvatarURL({ extension: 'png', size: 256 });

  await webhookClient.send({
    content: finalContent.trim() || undefined,
    username,
    avatarURL,
    allowedMentions: { parse: [] }, // Never ping anyone
    files: files
  });
}

module.exports = { getOrCreateWebhook, sendAsUser };
