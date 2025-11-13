sudo apt install postgresql -y
sudo -u postgres psql -c "CREATE USER pyroxy_admin WITH PASSWORD 'aaddmmiinn';"
sudo -u postgres psql -c "CREATE DATABASE proxy_db OWNER pyroxy_admin;"
