#!/bin/bash
tmux new-session -d -s main "python3 /root/main.py"
echo "Сервер запущен в tmux."