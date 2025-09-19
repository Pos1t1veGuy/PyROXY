import sys, zipfile, os
from pathlib import Path
import time


BASE_DIR = Path(sys.executable if getattr(sys, 'frozen', False) else __file__).parent
my_name = 'updater.exe'


def main():
    try:
        if len(sys.argv) < 2:
            raise Exception("No archive path provided")
            sys.exit(1)

        zip_path = Path(sys.argv[1])
        if not zip_path.exists():
            raise Exception(f"Archive not found: {zip_path}")
            sys.exit(1)

        for _ in range(30):
            try:
                with zipfile.ZipFile(zip_path, "r") as z:
                    for member in z.namelist():
                        if Path(member).name.lower() == my_name.lower():
                            continue
                        z.extract(member, BASE_DIR)
                        break
            except PermissionError:
                time.sleep(1)

        os.remove(zip_path)

        print('[+] Update installed, restart the app')
        sys.exit(0)

    except Exception as ex:
        print(f"[e] updater: {ex}")

if __name__ == "__main__":
    main()
