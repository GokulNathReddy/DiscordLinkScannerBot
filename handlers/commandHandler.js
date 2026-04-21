// ============================================================
//  handlers/commandHandler.js  —  Owner-only commands
// ============================================================

const { getExceptionFileContents, addDomain, removeDomain } = require('../utils/exceptions');

// Time to wait before deleting command responses (ms)
const DELETE_TIMEOUT = 30000;
const DENIAL_TIMEOUT = 10000;

/**
 * Handle terminal-style commands from the server owner.
 * @param {import('discord.js').Message} message
 * @returns {Promise<boolean>} True if a command was handled, false otherwise
 */
async function handleCommand(message) {
  const content = message.content.trim();

  // We only respond to text starting with sudo or cat
  if (!content.startsWith('sudo ') && !content.startsWith('cat ')) {
    return false;
  }

  // Check owner permissions
  if (message.guild && message.guild.ownerId !== message.author.id) {
    const msg = await message.reply('```bash\nPermission denied\n```');
    setTimeout(() => msg.delete().catch(() => {}), DENIAL_TIMEOUT);
    return true;
  }

  let responseBody = '';

  try {
    if (content === 'sudo ls') {
      const { admin, user } = getExceptionFileContents();
      responseBody = 
`root@discord-bot:~# ls -l exceptions/
--- adminexceptions.txt ---
${admin}

--- userexceptions.txt ---
${user}`;
    } 
    else if (content === 'cat adminexceptions.txt') {
      const { admin } = getExceptionFileContents();
      responseBody = `root@discord-bot:~# cat adminexceptions.txt\n${admin}`;
    } 
    else if (content === 'cat userexceptions.txt') {
      const { user } = getExceptionFileContents();
      responseBody = `root@discord-bot:~# cat userexceptions.txt\n${user}`;
    } 
    // sudo "domain.com" >> adminexceptions.txt
    else if (/^sudo\s+"([^"]+)"\s+>>\s+(adminexceptions\.txt|userexceptions\.txt)$/.test(content)) {
      const match = content.match(/^sudo\s+"([^"]+)"\s+>>\s+(adminexceptions\.txt|userexceptions\.txt)$/);
      const domain = match[1];
      const file = match[2] === 'adminexceptions.txt' ? 'admin' : 'user';
      const res = addDomain(file, domain);
      responseBody = `root@discord-bot:~# ${content}\n${res.message}`;
    }
    // sudo sed -i "domain.com" adminexceptions.txt
    else if (/^sudo\s+sed\s+-i\s+"([^"]+)"\s+(adminexceptions\.txt|userexceptions\.txt)$/.test(content)) {
      const match = content.match(/^sudo\s+sed\s+-i\s+"([^"]+)"\s+(adminexceptions\.txt|userexceptions\.txt)$/);
      const domain = match[1];
      const file = match[2] === 'adminexceptions.txt' ? 'admin' : 'user';
      const res = removeDomain(file, domain);
      responseBody = `root@discord-bot:~# ${content}\n${res.message}`;
    } 
    else {
      responseBody = `root@discord-bot:~# ${content}\nbash: command not found or invalid format`;
    }
  } catch (err) {
    responseBody = `root@discord-bot:~# ${content}\nError: ${err.message}`;
  }

  // Reply with standard terminal formatting
  const replyContent = `\`\`\`bash\n${responseBody}\n\`\`\``;
  const replyMsg = await message.reply(replyContent);

  // Auto delete original and reply
  setTimeout(() => message.delete().catch(() => {}), DELETE_TIMEOUT);
  setTimeout(() => replyMsg.delete().catch(() => {}), DELETE_TIMEOUT);

  return true;
}

module.exports = { handleCommand };
