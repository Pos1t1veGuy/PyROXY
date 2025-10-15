read -rp "[?] Enter your proxy domain: " DOMAIN
read -rp "[?] Enter your email: " EMAIL
echo "[*] Using domain: $DOMAIN"

sudo update-alternatives --config python3
echo "[*] installing the certbot"
sudo apt install certbot
echo "[*] setting up the certificate"
sudo systemctl stop nginx
sudo certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"

echo "[*] making nginx.conf..."
cat << EOF | sudo tee /etc/nginx/https_stream.conf > /dev/null
server {
    listen 443 ssl;
    proxy_protocol on;
    proxy_pass proxy_backend;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
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
    include /etc/nginx/https_stream.conf;
}
EOF

echo "[*] Enabling config..."
sudo nginx -t

echo "[*] Restarting nginx..."
sudo systemctl restart nginx

echo "[*] Setting up automatic certificate renewal..."
sudo bash -c "cat > /etc/cron.d/certbot-renew <<CRON
0 3 * * * root certbot renew --quiet --post-hook 'systemctl reload nginx'
CRON"

sudo update-alternatives --config python3
echo "[✓] HTTPS setup complete!"