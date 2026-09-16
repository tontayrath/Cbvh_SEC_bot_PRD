module.exports = {
  apps : [{
    name: "ExeGuardBot",
    script: "./Main.py",
    interpreter: "python", // On Windows, ensure 'python' is in PATH. If using venv, specify full path to python.exe
    watch: false,
    autorestart: true,
    max_memory_restart: "1G",
    env: {
      NODE_ENV: "development",
    },
    env_production: {
      NODE_ENV: "production",
    }
  }]
};
