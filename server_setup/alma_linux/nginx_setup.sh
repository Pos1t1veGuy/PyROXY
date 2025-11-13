#!/bin/bash
set -e

echo "[*] installing nginx..."
sudo dnf -y update
sudo dnf -y install epel-release
sudo dnf -y install nginx nginx-mod-stream

echo "[*] making nginx.conf..."
cat << 'EOF' | sudo tee /etc/nginx/default_stream.conf > /dev/null
limit_conn_zone $binary_remote_addr zone=addr:10m;

server {
    listen 80;
    proxy_protocol on;

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
load_module /usr/lib64/nginx/modules/ngx_stream_module.so;

user nginx;
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
