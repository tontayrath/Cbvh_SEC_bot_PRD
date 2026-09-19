@echo off
echo Step 1: Switching to D Drive...
D:

echo Step 2: Navigating to the Bot Folder...
cd "D:\Tontay\Telegram Bot\Cbvh_SEC_bot_PRD"

echo Step 3: Installing required packages...
:: This will install missing packages. If they are already installed, pip simply skips them.
pip install -r requirements.txt

echo.
echo Step 4: Starting the Telegram Bot...
python Main.py

echo.
echo =========================================
echo THE SCRIPT HAS CRASHED OR STOPPED.
echo =========================================
pause