require('dotenv').config();

module.exports = {
  // Your bot token from https://discord.com/developers/applications
  token: process.env.DISCORD_BOT_TOKEN,

  apis: {
    ipqs: {
      enabled: true,
      apiKey: process.env.IPQS_API_KEY,
    },
    virustotal: {
      enabled: true,
      apiKey: process.env.VIRUSTOTAL_API_KEY,
    },
  },

  // Channel ID of your mod-log / security-log channel
  logChannelId: process.env.MOD_LOG_CHANNEL_ID,
};
