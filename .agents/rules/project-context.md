# Project Context — Cbvh_SEC_bot_PRD

## Overview
This is the **Cbvh SEC Telegram Bot** (Production). It is a Python-based Telegram bot.

## Architecture & Server Specs
- **Server Hardware:** 4-core processor (Intel Xeon), 8GB DDR4 RAM, 256GB SSD
- **Performance Constraint:** Always warn the user if a requested feature might cause CPU/RAM overload or slow down bot response times. Optimize code specifically for these constraints.
- **Dev PC** (D: drive) → push code to **GitHub** → pull code on **Windows Server 2016** (F: drive, IP: 192.168.11.26)
- Terminal on the server: **Git Bash (MINGW64)**
- The agent (Antigravity) runs on the **Dev PC**, NOT on the server.

## Paths
| Environment | Path |
|-------------|------|
| Dev PC | `D:\Tontay\Telegram Bot\Cbvh_SEC_bot_PRD` |
| Server | `F:\Tontay\Cbvh_Project\Cbvh_SEC_bot_PRD` |
| GitHub | `https://github.com/tontayrath/Cbvh_SEC_bot_PRD` |

## PM2 (Server)
- Process name: `@Cbvh_SEC_bot_PRD`
- Start: `pm2 start ecosystem.config.js`
- Restart: `pm2 restart @Cbvh_SEC_bot_PRD`
- Always run `pm2 save` after changes

## Workflow
1. Make changes and test locally: `python Main.py`
2. Push: `git add . && git commit -m "message" && git push`
3. On the server (Git Bash): `cd /f/Tontay/Cbvh_Project/Cbvh_SEC_bot_PRD && git pull && pm2 restart @Cbvh_SEC_bot_PRD && pm2 save`

## Related Projects
- **VH_SEC_bot_PRD** — sister bot at `D:\Tontay\Telegram Bot\VH_SEC_bot_PRD`
- **telegram-bot-management-system** — Next.js dashboard at `D:\Tontay\Bot management project\telegram-bot-management-system`
- Full workflow guide: `D:\Tontay\Bot management project\WORKFLOW.md`
