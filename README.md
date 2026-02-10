# Perversions, Darkness, and Death: Fedora Bash Aliases

My personal collection of "crutches" and automation scripts for Fedora Linux. These aliases are designed to minimize typing, handle Wayland clipboard quirks, and provide paranoid-level system reporting.

## 🛠 Features

### 🚀 System Management
* **`upall`**: The ultimate update command. Refreshes DNF, updates Flatpaks, and deep-cleans the cache in one go.
* **`suka`**: The "Machine Uprising" command. Re-runs your last command with `sudo` privileges if you forgot them.
* **`sysrep`**: A comprehensive health report including RAM, failed systemd units, and external IP tracking.

### 🕵️ Privacy & Security
* **`anon`**: Packs files into `.tar.xz` with maximum compression, scrubs owner/group info, and spoofs the creation date to the Unix Epoch (1970-01-01).
* **`net_watchdog`**: Audits external network services, mapping PIDs to services and checking their status in the Fedora firewall.
* **`genpass`**: Generates high-entropy passwords directly from `/dev/urandom`.

### 📂 Navigation & Workflow
* **`up N`**: Move up N directory levels effortlessly.
* **`cpy` / `pst`**: Native Wayland clipboard support using `wl-copy` and `wl-paste`.
* **`note`**: A quick-and-dirty CLI notepad that saves entries to `~/Documents/BashNotes/`.

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/fedora-aliases.git](https://github.com/yourusername/fedora-aliases.git)
   cd fedora-aliases
   ```

2. **The Fedora Way (Recommended):**
   Fedora is set up to source scripts from `~/.bashrc.d/`. Simply copy the file there:
   ```bash
   mkdir -p ~/.bashrc.d/
   cp 10-aliases.sh ~/.bashrc.d/
   ```

3. **Manual Sourcing:**
   Alternatively, add the following line to the end of your `~/.bashrc`:
   ```bash
   source /path/to/10-aliases.sh
   ```

4. **Reload:**
   ```bash
   source ~/.bashrc
   ```

## 📋 Dependencies

To use the full power of these aliases, ensure the following are installed:
* `dnf` & `flatpak` (Standard in Fedora)
* `nmap` (For `net_radar`)
* `wl-clipboard` (For Wayland copy/paste)
* `rsync` (For progress-aware copying)
* `curl` (For weather and IP info)

## ⚖️ License
This project is licensed under the MIT License—use it, break it, just don't blame me when your terminal starts judging you.
