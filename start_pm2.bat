@echo off
echo Starting PM2 for ExeGuardBot...

:: Check if pm2 is installed
pm2 -v >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo PM2 is not installed. Please install Node.js and run:
    echo npm install -g pm2
    pause
    exit /b
)

:: Start or restart the bot via ecosystem file
pm2 start ecosystem.config.js
pm2 save

echo.
echo PM2 has started the bot!
echo You can use 'pm2 log ExeGuardBot' to see the logs.
echo You can use 'pm2 monit' to monitor the process.
pause
