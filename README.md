> [!WARNING]
> ### ⚠️ Disclaimer: Fully AI-Generated Code & Work In Progress (WIP)
> This repository and its entire codebase are **100% AI-generated**.
> This project is an active **Work In Progress (WIP)**. It is provided for experimental and demonstration purposes; features, system metrics, and low-level kernel APIs may evolve, and unexpected bugs or limitations may be present. Use at your own discretion.

# TMM — Task Manager For Mac

A modern, native macOS task manager and system monitor **inspired by Windows Task Manager**, reimagined with native macOS System Settings styling, built with pure Swift and AppKit with zero third-party dependencies.

TMM bridges the best of both worlds: the rich diagnostics, live sparklines, per-core telemetry, and detailed process management familiar from Windows Task Manager, combined with the clean aesthetics, vibrancy, and fluid feel of macOS.

---

## ⬇️ Direct Download

You can download the pre-compiled, Universal 2 macOS installer directly:

* **[⬇️ Direct Download: TaskMonitor.dmg](https://github.com/itsarjunc/TMM-Task-Manager-For-Mac/raw/main/TaskMonitor.dmg)** *(Hosted directly in this repository)*
* **[📦 GitHub Releases (v1.0.0)](https://github.com/itsarjunc/TMM-Task-Manager-For-Mac/releases/latest)**

> **Compatibility**: Universal Binary (`arm64` Apple Silicon M1/M2/M3/M4 + `x86_64` Intel Macs) running macOS 13.0 Ventura or newer.

---

## 🚀 Installation & First Launch (Gatekeeper)

1. Download **[TaskMonitor.dmg](https://github.com/itsarjunc/TMM-Task-Manager-For-Mac/raw/main/TaskMonitor.dmg)**.
2. Double-click the DMG and drag **Task Monitor** into your **Applications** folder.
3. **Note on First Launch**: Because this is an independently distributed open-source app, macOS Gatekeeper may show a prompt:
   > *"TaskMonitor cannot be opened because Apple cannot check it for malicious software"*
   
   **How to open:**
   - **Method 1**: Right-click (or Control-click) `Task Monitor` in your Applications folder, click **Open**, then click **Open** in the confirmation dialog.
   - **Method 2**: Run this command in Terminal:
     ```bash
     xattr -cr /Applications/TaskMonitor.app
     ```

---

## ✨ Features

- **Processes**:
  - Live process table with process icons, status indicators, CPU %, Memory footprint, Disk I/O rate, Energy Impact, and thread count.
  - Search filter and multi-column sorting (CPU, Memory, Name, PID, etc.).
  - Persistent selection across 2-second live auto-refreshes.
  - Multi-selection support with direct termination via `⌫` (Delete/Backspace) or `End Task` button.
  - Right-click context menu (End Task, Force Quit, Show in Finder, Copy PID).

- **Performance**:
  - Processor utilization telemetry with real-time graphs and Apple Silicon chip detection (e.g. Apple M3).
  - **All-Core Breakdown**: Individual live sparkline load tiles for all Performance (P) and Efficiency (E) cores.
  - Memory pressure breakdown (Used, Wired, Compressed, App Memory, Cached, Free).
  - Disk read/write rates and Network throughput history sparklines.

- **Battery & Power**:
  - Real-time state of charge, power flow, and AC adapter wattage.
  - Battery health and longevity: Maximum capacity %, cycle count, design capacity, and degradation rate.
  - Electrical diagnostics: Voltage, current amperage, power draw in Watts, and battery controller IC.

- **Disk & S.M.A.R.T.**:
  - NVMe internal drive health telemetry and verified status.
  - Real-time drive temperature, available spare %, total data written/read (TB), power cycles, unsafe shutdowns, and data integrity error tracking.
  - Volume capacity allocation bar.

- **macOS Native Design**:
  - Full-height, end-to-end sidebar with native macOS visual effects.
  - Colorful squircle icons matching macOS Settings.
  - Interactive `< | >` history navigation with keyboard shortcuts (`⌘1`, `⌘2`, `⌘3`, `⌘4`, `⌘[`, `⌘]`, `⌘R`, `⌘F`).
  - Hero header card matching macOS System Settings.
  - Liquid Glass materials (`NSGlassEffectView` on macOS 26+ with automatic fallback for macOS 13+).

---

## 🛠️ Building & Packaging

### Prerequisites
- macOS 13.0 or later
- Swift Command Line Tools (`xcode-select --install`)

### Compile Application
```bash
./build.sh
```
This builds a Universal 2 binary (`arm64` + `x86_64`) inside `TaskMonitor.app`.

### Build Shareable DMG
```bash
./create_dmg.sh
```
This creates `TaskMonitor.dmg` with the app bundle, an `/Applications` drag-and-drop symlink, and installation instructions.

---

## 📄 License
MIT License
