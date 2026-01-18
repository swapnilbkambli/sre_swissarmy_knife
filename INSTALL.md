# Installation Guide

Follow these steps to set up OpsNexus on your machine.

## 📋 Prerequisites

- Python 3.9 or higher
- `pip` (Python package manager)
- **Key Libraries**: `flet`, `pynput`, `Pillow`, `croniter`, `PyYAML`

## ⚙️ Standard Installation

1. **Clone the repository** (if applicable) or navigate to the project directory.
2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:

   ```bash
   python3 main.py
   ```

---

## 📂 Configuration Storage

OpsNexus uses a persistent configuration file to store your settings, pinned tabs, and usage data. This ensures your preferences are preserved across updates.

- **macOS/Linux**: `~/.opsnexus/config.json`
- **Windows**: `C:\Users\<Username>\.opsnexus\config.json`

---

## 📖 How to Use Quick Access

OpsNexus includes an intelligent **Quick Access Bar** at the top of the interface to help you switch between tools faster.

### 📍 Manual Pinning

1. Click the **Settings** (gear) icon in the top right.
2. In the **Pin** column, check the boxes for the utilities you use most frequently.
3. Click **Save & Restart**.
4. Your pinned tools will now always appear as icons in the absolute center of the header.

### 🧠 Smart Usage Tracking

Even if you don't pin any tools, OpsNexus watches which tabs you switch to most often. It dynamically fills the remaining slots (up to 5 total) with your most-used enabled utilities. As your workflow changes, the bar will automatically adapt to keep your most relevant tools one click away.

---

## 🍎 macOS Specific Instructions

On macOS, the secondary library `pynput` (used for the global hotkey) requires special system permissions to listen for the `Option + H` trigger while the app is in the background.

### Resolving "Process is not trusted" error

If you see an error about "Input event monitoring" or "Process is not trusted", follow these steps:

1. Open **System Settings** (formerly System Preferences).
2. Navigate to **Privacy & Security** > **Accessibility**.
3. Look for your terminal application in the list (e.g., **Terminal**, **iTerm2**, or **VS Code**).
4. **Toggle the switch ON** for that application.
5. If the application is not in the list, click the **+** (plus) button and add it from your `/Applications` or `/System/Applications/Utilities` folder.
6. **Restart your terminal** and run the script again.

> [!NOTE]  
> If you prefer not to grant these permissions, the app will still function perfectly, but the global hotkey (`Option + H`) will be disabled.

---

## 🏗️ Building a Standalone Executable

If you want to build a standalone `.app` (macOS) or `.exe` (Windows) file:

### 🪟 Windows Instructions

1. Install PyInstaller:

   ```bash
   pip install pyinstaller
   ```

2. Run the build script:

   ```bash
   python build_app.py
   ```

   *The portable `OpsNexus.exe` will be located in the `dist/` folder.*

### 🍎 macOS Instructions

1. Install build tools:

   ```bash
   pip install flet
   ```

2. Run the build script:

   ```bash
   python3 build_app.py
   ```

   *The `OpsNexus.app` bundle will be located in the `dist/` folder.*
