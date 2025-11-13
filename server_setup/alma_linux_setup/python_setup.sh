sudo dnf -y update
sudo dnf -y groupinstall "Development Tools"

sudo dnf -y install \
    openssl-devel \
    bzip2-devel \
    libffi-devel \
    zlib-devel \
    readline-devel \
    sqlite-devel \
    tk-devel \
    gdbm-devel \
    xz-devel \
    wget \
    curl

cd /usr/src
sudo wget https://www.python.org/ftp/python/3.13.0/Python-3.13.0.tgz
sudo tar xvf Python-3.13.0.tgz
cd Python-3.13.0

sudo ./configure --enable-optimizations --with-ensurepip=install
sudo make -j$(nproc)
sudo make altinstall

sudo alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 10
sudo alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.13 20
sudo alternatives --config python3

/usr/local/bin/python3.13 -m ensurepip --upgrade
/usr/local/bin/python3.13 -m pip install --upgrade pip setuptools wheel

python3 --version
python3 -m pip --version