sudo apt update
sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev \
  libncurses5-dev libffi-dev libsqlite3-dev libreadline-dev \
  libtk8.6 libgdbm-dev wget curl libbz2-dev liblzma-dev

cd /usr/src
sudo wget https://www.python.org/ftp/python/3.13.0/Python-3.13.0.tgz
sudo tar xvf Python-3.13.0.tgz
cd Python-3.13.0

sudo ./configure --enable-optimizations --with-ensurepip=install
sudo make -j$(nproc)
sudo make altinstall

sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 10
sudo update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.13 20
sudo update-alternatives --config python3

/usr/local/bin/python3.13 -m ensurepip --upgrade
/usr/local/bin/python3.13 -m pip install --upgrade pip setuptools wheel

python3 --version
python3 -m pip --version