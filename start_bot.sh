#!/bin/bash
tmux new-session -d -s bot "python3 -m pyroxy.telegram_bot.main > /root/bot.log 2>&1"
echo "Бот запущен в tmux."