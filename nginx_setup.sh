#!/bin/bash
set -e

echo "[*] installing nginx..."
sudo apt update -y
sudo apt install -y nginx
sudo apt-get install libnginx-mod-stream

echo "[*] making nginx.conf..."
cat << 'EOF' | sudo tee /etc/nginx/default_stream.conf > /dev/null

limit_conn_zone $binary_remote_addr zone=addr:10m;

server {
    listen 80;

    # Ограничения
    proxy_connect_timeout 5s;
    proxy_timeout 240s;

    # Количество соединений
    limit_conn addr 300;

    # Логи
    access_log /var/log/nginx/proxy_access.log basic;
    error_log /var/log/nginx/proxy_error.log warn;

    proxy_pass proxy_backend;
}
EOF
cat << 'EOF' | sudo tee /etc/nginx/nginx.conf > /dev/null
load_module /usr/lib/nginx/modules/ngx_stream_module.so;

user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

stream {
    log_format basic '$remote_addr [$time_local] '
                     '$protocol $status $bytes_sent $bytes_received '
                     '$session_time';

    upstream proxy_backend {
        server 127.0.0.1:8080;
    }

    include /etc/nginx/default_stream.conf;
}
EOF

sudo update-alternatives --config python3
echo "[*] Enabling config..."
sudo nginx -t

echo "[*] Restarting nginx..."
sudo systemctl restart nginx

sudo update-alternatives --config python3
echo "[+] Done!"
