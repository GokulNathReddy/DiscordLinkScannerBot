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

  // Check permissions: Must be Owner OR have Administrator permission
  const isOwner = message.guild && message.guild.ownerId === message.author.id;
  const isAdmin = message.member?.permissions.has(require('discord.js').PermissionFlagsBits.Administrator);

  if (message.guild && !isOwner && !isAdmin) {
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
    else if (content === 'sudo cat timeout.txt') {
      const { getTimeoutRecords } = require('../utils/timeoutManager');
      responseBody = `root@discord-bot:~# ${content}\n${getTimeoutRecords()}`;
    }
    else if (content.startsWith('sudo timeout ')) {
      const targetId = content.replace('sudo timeout ', '').replace(/[<@!>]/g, '').trim();
      const member = await message.guild.members.fetch(targetId).catch(() => null);
      if (!member) {
         responseBody = `root@discord-bot:~# ${content}\nError: User not found in server.`;
      } else {
         const { manualTimeout } = require('../utils/timeoutManager');
         await manualTimeout(member, 'Manual Timeout by Admin via Bot Terminal');
         responseBody = `root@discord-bot:~# ${content}\nSuccessfully timed out ${member.user.tag} for 24 hours.`;
      }
    }
    else if (content.startsWith('sudo antitimeout ')) {
      const targetId = content.replace('sudo antitimeout ', '').replace(/[<@!>]/g, '').trim();
      const member = await message.guild.members.fetch(targetId).catch(() => null);
      if (!member) {
         responseBody = `root@discord-bot:~# ${content}\nError: User not found in server.`;
      } else {
         const { removeTimeout } = require('../utils/timeoutManager');
         await removeTimeout(member);
         responseBody = `root@discord-bot:~# ${content}\nSuccessfully removed timeout for ${member.user.tag}.`;
      }
    }
    else if (content.startsWith('sudo ban ')) {
      const targetId = content.replace('sudo ban ', '').replace(/[<@!>]/g, '').trim();
      const member = await message.guild.members.fetch(targetId).catch(() => null);
      if (!member) {
         responseBody = `root@discord-bot:~# ${content}\nError: User not found in server.`;
      } else {
         await member.ban({ reason: 'Banned by Admin via Bot Terminal' });
         responseBody = `root@discord-bot:~# ${content}\nSuccessfully banned ${member.user.tag}.`;
      }
    }
    else if (content.startsWith('sudo unban ')) {
      const targetId = content.replace('sudo unban ', '').replace(/[<@!>]/g, '').trim();
      if (!targetId) {
         responseBody = `root@discord-bot:~# ${content}\nError: Please provide a valid User ID.`;
      } else {
         try {
            await message.guild.bans.remove(targetId, 'Unbanned by Admin via Bot Terminal');
            responseBody = `root@discord-bot:~# ${content}\nSuccessfully unbanned user ID ${targetId}.`;
         } catch (err) {
            responseBody = `root@discord-bot:~# ${content}\nError: Failed to unban user. They might not be banned or the ID is invalid.`;
         }
      }
    }
    else if (content.startsWith('sudo kick ')) {
      const targetId = content.replace('sudo kick ', '').replace(/[<@!>]/g, '').trim();
      const member = await message.guild.members.fetch(targetId).catch(() => null);
      if (!member) {
         responseBody = `root@discord-bot:~# ${content}\nError: User not found in server.`;
      } else {
         await member.kick('Kicked by Admin via Bot Terminal');
         responseBody = `root@discord-bot:~# ${content}\nSuccessfully kicked ${member.user.tag}.`;
      }
    }
    else if (content === 'sudo neofetch') {
      const os = require('os');
      const djsVersion = require('discord.js').version;
      
      const formatUptime = (seconds) => {
         const d = Math.floor(seconds / 86400);
         const h = Math.floor(seconds / 3600) % 24;
         const m = Math.floor(seconds / 60) % 60;
         const s = Math.floor(seconds % 60);
         return `${d}d ${h}h ${m}m ${s}s`;
      };

      const sysUptimeStr = formatUptime(os.uptime());
      const botUptimeStr = formatUptime(process.uptime());
      
      const sysMemoryTotal = (os.totalmem() / 1024 / 1024 / 1024).toFixed(2);
      const sysMemoryUsed = ((os.totalmem() - os.freemem()) / 1024 / 1024 / 1024).toFixed(2);
      const botMemoryUsed = (process.memoryUsage().rss / 1024 / 1024).toFixed(2);
      
      const cpuModel = os.cpus()[0].model.trim();
      const cpuCores = os.cpus().length;
      
      const ping = message.client.ws.ping;
      const guild = message.guild;
      const members = guild ? guild.memberCount : 0;
      const channels = guild ? guild.channels.cache.size : 0;
      const roles = guild ? guild.roles.cache.size : 0;
      const serverName = guild ? guild.name : 'Unknown';
      
      responseBody = `root@discord-bot:~# ${content}\n` +
`       .---.       root@${os.hostname()}
      /     \\      -------------------------
     | () () |     OS: ${os.type()} ${os.release()} ${os.arch()}
      \\  ^  /      Uptime (System): ${sysUptimeStr}
       |||||       Uptime (Bot): ${botUptimeStr}
       |||||       CPU: ${cpuModel} (${cpuCores} Cores)
                   Memory (System): ${sysMemoryUsed}GiB / ${sysMemoryTotal}GiB
                   Memory (Bot Usage): ${botMemoryUsed}MiB
                   
                   --- SOFTWARE ---
                   Node.js: ${process.version}
                   Discord.js: v${djsVersion}
                   
                   --- DISCORD STATS ---
                   Server: ${serverName}
                   Members: ${members}
                   Channels: ${channels}
                   Roles: ${roles}
                   Bot Latency: ${ping}ms`;
    }
    else if (content === 'sudo help') {
      responseBody = `root@discord-bot:~# ${content}\n` +
        `--- BOT TERMINAL COMMANDS (ADMIN ONLY) ---\n` +
        `sudo ls                                 - List exception files\n` +
        `cat adminexceptions.txt                 - View admin exceptions\n` +
        `cat userexceptions.txt                  - View user exceptions\n` +
        `sudo "domain.com" >> <file>             - Add domain to exceptions\n` +
        `sudo sed -i "domain.com" <file>         - Remove domain from exceptions\n` +
        `sudo cat timeout.txt                    - View currently timed out users\n` +
        `sudo timeout @user                      - Manually timeout a user for 24h\n` +
        `sudo antitimeout @user                  - Manually remove a timeout\n` +
        `sudo kick @user                         - Kick a user from the server\n` +
        `sudo ban @user                          - Ban a user from the server\n` +
        `sudo unban <id>                         - Unban a user by their ID\n` +
        `sudo neofetch                           - View bot server stats\n` +
        `sudo help                               - Display this help message`;
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
