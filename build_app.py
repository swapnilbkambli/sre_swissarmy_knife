import os
import subprocess
import sys

def build():
    print("Starting build process for OpsNexus...")
    
    # Check if flet is installed
    try:
        import flet
    except ImportError:
        print("Error: flet not found. Please run 'pip install flet'")
        return

    import platform
    is_mac = platform.system() == "Darwin"

    # Base PyInstaller command
    command = [
        sys.executable, "-m", "PyInstaller",
        "main.py",
        "--name", "OpsNexus",
        "--noconfirm",
        "--clean",
    ]

    if is_mac:
        # macOS: Needs onedir and windowed for proper .app bundle and Dock icon
        command.extend(["--onedir", "--windowed"])
    else:
        # Windows/Linux: onefile is usually preferred and simpler
        command.extend(["--onefile", "--noconsole"])
    
    icon_file = "icon.png"
    if os.path.exists("assets/icon.png"):
        icon_file = "assets/icon.png"
    
    if os.path.exists(icon_file):
        command.extend(["--icon", icon_file])
    
    if os.path.exists("assets"):
        # Include assets folder in the bundle (source:destination)
        command.extend(["--add-data", "assets:assets"])
    
    print(f"Running command: {' '.join(command)}")
    try:
        subprocess.run(command, check=True)
        print("\nBuild successful! Check the 'dist/OpsNexus.app' for your application.")
    except subprocess.CalledProcessError as e:
        print(f"\nBuild failed: {e}")

if __name__ == "__main__":
    build()
