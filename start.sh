#!/bin/bash
tmux new-session -d -s main "python3 /root/main.py"
tmux new-session -d -s bot "cd /root/pyroxy/telegram_bot && python3 main.py > /root/bot.log 2>&1"
echo "Сервер и бот запущены в tmux."