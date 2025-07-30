import sys, subprocess

modules = ['ciphers', 'wrappers']

for name in modules:
    path = f"./{name}/requirements.txt"
    subprocess.run(["pip", "install", "-r", path], check=True)