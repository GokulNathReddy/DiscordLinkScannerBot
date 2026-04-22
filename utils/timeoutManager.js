const fs = require('fs');
const path = require('path');

const TIMEOUT_FILE = path.join(__dirname, '..', 'timeout.txt');

// Ensure the file exists
if (!fs.existsSync(TIMEOUT_FILE)) {
  fs.writeFileSync(TIMEOUT_FILE, '', 'utf8');
}

// In-memory strike tracking: { userId: { count, firstStrikeTime } }
const userStrikes = new Map();
const STRIKE_THRESHOLD = 3;
const STRIKE_DECAY_MS = 60 * 1000; // 60 seconds strict window
const TIMEOUT_DURATION_MS = 24 * 60 * 60 * 1000; // 24 hours timeout

/**
 * Clean up old strikes
 */
function cleanupStrikes() {
  const now = Date.now();
  for (const [userId, data] of userStrikes.entries()) {
    if (now - data.firstStrikeTime > STRIKE_DECAY_MS) {
      userStrikes.delete(userId);
    }
  }
}
setInterval(cleanupStrikes, 10000); // Clean up every 10 seconds for higher accuracy

/**
 * Add an infraction strike to a user. Over threshold limits them.
 * @param {import('discord.js').GuildMember} member
 */
async function addStrike(member) {
  if (!member) return; // Can't strike if not a member

  cleanupStrikes();
  
  // Create a strict 60-second absolute window
  let data = userStrikes.get(member.id) || { count: 0, firstStrikeTime: Date.now() };
  data.count += 1;
  userStrikes.set(member.id, data);

  if (data.count >= STRIKE_THRESHOLD) {
    // Auto-timeout
    try {
      await manualTimeout(member, 'Auto-timeout: Repeated severe infractions (Spamming malicious links/invites)');
    } catch (e) {
      console.error(`[timeoutManager] Failed to auto-timeout ${member.user.tag}:`, e.message);
    }
    userStrikes.delete(member.id); // Always reset strikes after hitting threshold
  }
}

/**
 * Manually timeout a user
 * @param {import('discord.js').GuildMember} member
 * @param {string} reason
 */
async function manualTimeout(member, reason = 'Administrative Action') {
  if (!member.moderatable) {
    throw new Error('Bot lacks permission to timeout this user (they likely have a higher role).');
  }

  await member.timeout(TIMEOUT_DURATION_MS, reason);
  recordTimeout(member.user.tag, member.id, reason);
}

/**
 * Manually remove timeout from a user
 * @param {import('discord.js').GuildMember} member
 */
async function removeTimeout(member) {
  if (!member.moderatable) {
    throw new Error('Bot lacks permission to modify this user.');
  }

  await member.timeout(null, 'Administrator removed timeout');
  removeRecord(member.id);
}

/**
 * Record timeout to timeout.txt
 */
function recordTimeout(tag, id, reason) {
  let content = fs.readFileSync(TIMEOUT_FILE, 'utf8');
  const entry = `[${new Date().toISOString()}] USER: ${tag} (ID: ${id}) | REASON: ${reason}\n`;
  if (!content.includes(id)) {
    fs.appendFileSync(TIMEOUT_FILE, entry, 'utf8');
  }
}

/**
 * Remove timeout record from timeout.txt
 */
function removeRecord(id) {
  let content = fs.readFileSync(TIMEOUT_FILE, 'utf8');
  const lines = content.split('\n');
  const newLines = lines.filter(line => !line.includes(`(ID: ${id})`));
  fs.writeFileSync(TIMEOUT_FILE, newLines.join('\n'), 'utf8');
}

/**
 * Read timeout.txt
 */
function getTimeoutRecords() {
  return fs.readFileSync(TIMEOUT_FILE, 'utf8') || 'No users currently timed out.';
}

module.exports = {
  addStrike,
  manualTimeout,
  removeTimeout,
  getTimeoutRecords
};
