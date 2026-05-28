// PM2 ecosystem file for a single-VM deployment of Threat Watcher.
// Usage:
//   pm2 start deploy/pm2.ecosystem.config.js --env production
//   pm2 save && pm2 startup     # systemd-managed PM2 daemon
//
// Both processes read env from their respective .env files (loaded by dotenv
// in src/config). Anything overridden below takes precedence.

module.exports = {
  apps: [
    {
      name: "tw-backend",
      cwd: "./backend",
      script: "src/server.js",
      instances: 1,
      exec_mode: "fork",
      kill_timeout: 10_000,
      max_memory_restart: "512M",
      // Stream pino JSON to PM2 logs; pm2-logrotate handles rotation.
      out_file: "/var/log/threat-watcher/backend.out.log",
      error_file: "/var/log/threat-watcher/backend.err.log",
      env: { NODE_ENV: "production" },
      env_production: { NODE_ENV: "production" },
    },
    {
      name: "tw-frontend",
      cwd: "./frontend",
      script: "src/server.js",
      instances: 1,
      exec_mode: "fork",
      kill_timeout: 10_000,
      max_memory_restart: "256M",
      out_file: "/var/log/threat-watcher/frontend.out.log",
      error_file: "/var/log/threat-watcher/frontend.err.log",
      env: { NODE_ENV: "production" },
      env_production: { NODE_ENV: "production" },
    },
  ],
};
