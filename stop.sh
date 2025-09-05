#!/bin/bash
tmux kill-session -t main 2>/dev/null
tmux kill-session -t bot 2>/dev/null
echo "Сервер и бот остановлены."