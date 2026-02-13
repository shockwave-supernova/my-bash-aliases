# =============================================================================
# BASH ALIASES AND FUNCTIONS
# =============================================================================
#
# This file contains custom Bash aliases and functions for interactive shells.
# Designed for Fedora (or any system where ~/.bashrc is used).
#
# ---------------------------------------------------------------------------
# Location:
#   ~/.bashrc.d/10-aliases.sh
#
# ---------------------------------------------------------------------------
# How it works:
#   1. Fedora does not use ~/.bash_aliases by default.
#   2. To keep things organized, you can place multiple Bash config
#      fragments in ~/.bashrc.d/ and source them from ~/.bashrc.
#   3. Numbering files (e.g., 10-aliases.sh, 20-functions.sh) allows
#      control over load order.
#
# ---------------------------------------------------------------------------
# Setup instructions:
#   a) Ensure ~/.bashrc sources all files in ~/.bashrc.d/:
#
#      if [ -d "$HOME/.bashrc.d" ]; then
#          for file in "$HOME/.bashrc.d/"*.sh; do
#              [ -r "$file" ] && . "$file"
#          done
#      fi
#
#   b) Place this file in ~/.bashrc.d/10-aliases.sh
#   c) Add your aliases and functions below this header.
#   d) Open a new terminal or run `source ~/.bashrc` to apply changes.
#
# ---------------------------------------------------------------------------
# Notes:
#   - Keep aliases simple and clear.
#   - Functions should be interactive-friendly.
#   - You can create additional files for organization:
#       ~/.bashrc.d/20-functions.sh
#       ~/.bashrc.d/30-network-tools.sh
#   - Use numbering to control load order.
#
# =============================================================================

# =============================================================================
# SYSTEM & UPDATES
# =============================================================================
#
# This section contains aliases and functions for managing the system,
# performing package updates, and cleaning up.
#
# Usage examples:
#   update          → Refresh and upgrade all DNF packages
#   upall           → Upgrade all DNF and Flatpak packages, clean cache
#   inst <package>  → Install a package
#   uninst <pkg>    → Remove a package
#   clean           → Clean unnecessary packages and cache
#   pls <command>   → Retry last failed command with sudo
#   reload          → Reload this shell configuration
#   off             → Shutdown immediately
#   reboot          → Reboot immediately
#
# Notes:
#   - Fedora uses DNF as the package manager; update and upgrade are the same.
#   - Flatpak packages are managed separately.
#   - Use numbering in ~/.bashrc.d to control load order (e.g., 10-aliases.sh).
# =============================================================================

# Refresh package metadata and upgrade all DNF packages
alias update='sudo dnf upgrade --refresh'

# Upgrade DNF and Flatpak, remove unneeded packages, clean cache
alias upall='sudo dnf upgrade --refresh -y && flatpak update -y && sudo dnf autoremove -y && sudo dnf clean all'

# Install a package quickly
# Example: inst vlc
alias inst='sudo dnf install'

# Remove a package
alias uninst='sudo dnf remove'

# Clean unnecessary packages and DNF cache
alias clean='sudo dnf autoremove && sudo dnf clean all'

# Re-run the last command with sudo
# Example:
#   dnf install htop       → fails with permission denied
#   pls                     → reruns as sudo dnf install htop
alias pls='sudo $(history -p !!)'

# Clear the terminal
alias c='clear'

# Reload Bash configuration
alias reload='source ~/.bashrc; echo "Terminal settings reloaded!"'

# Quick shutdown and reboot
alias off='sudo shutdown -h now'
alias reboot='sudo reboot'


# =============================================================================
# --- SYSTEM REPORT ---
# Shows disk usage, memory & swap, load average, failed systemd units,
# Lightweight system health overview for modern Linux systems.
# Designed for NetworkManager-based setups (Fedora, etc.).
# =============================================================================

sysrep() {
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'

    # --- Header ---
    echo -e "${YELLOW}=== SYSTEM ANALYSIS: $(hostname) ===${NC}"
    echo "Time: $(date)"
    echo "---------------------------------------------------"

    # --- Disk usage (root filesystem) ---
    root_usage=$(df --output=pcent / | tail -1 | tr -dc '0-9')
    [[ ! "$root_usage" =~ ^[0-9]+$ ]] && root_usage=0

    echo -n "Root Usage: "
    if [ "$root_usage" -gt 90 ]; then
        echo -e "${RED}${root_usage}% (CRITICAL)${NC}"
    else
        echo -e "${GREEN}${root_usage}%${NC}"
    fi

    # --- Memory ---
    echo -e "\nMemory (RAM):"
    free -h | awk '/^Mem:/ {printf "Used: %s / Total: %s\n", $3, $2}'

    echo "Swap:"
    free -h | awk '/^Swap:/ {printf "Used: %s / Total: %s\n", $3, $2}'

    # --- Load average vs CPU cores ---
    echo -e "\nLoad Average:"
    load=$(uptime | awk -F'load average:' '{print $2}' | sed 's/^[[:space:]]*//')
    cores=$(nproc)
    load1min=$(echo "$load" | cut -d, -f1 | tr -d ' ')
    load1min_int=${load1min%.*}

    if (( load1min_int > cores )); then
        echo -e "${RED}$load${NC}"
    else
        echo -e "${GREEN}$load${NC}"
    fi

    # --- Failed systemd units ---
    echo -e "\n${YELLOW}Failed Units:${NC}"
    failed=$(systemctl list-units --state=failed --no-legend)

    if [ -z "$failed" ]; then
        echo "None"
    else
        echo -e "${RED}$failed${NC}"
    fi

    # --- Top memory consumers ---
    echo -e "\n${YELLOW}Top Memory Consumers:${NC}"
    ps aux --sort=-%mem | head -n 6 \
        | awk '{printf "%-8s %-10s %-6s %s\n", $1, $2, $4 "%", $11}'

    # --- Last logged-in users ---
    echo -e "\n${YELLOW}Last Logged-in Users:${NC}"
    last -n 5 | awk '{print $1, $3, $4, $5, $6, $7}'

    # --- Network (local addresses only) ---
    echo -e "\n${YELLOW}Network Status:${NC}"

    ip4=$(ip -4 -o addr show scope global 2>/dev/null \
          | awk '{print $4}' | cut -d/ -f1)
    ip6=$(ip -6 -o addr show scope global 2>/dev/null \
          | awk '{print $4}' | cut -d/ -f1)

    [ -z "$ip4" ] && ip4="Not detected"
    [ -z "$ip6" ] && ip6="Not detected"

    echo -e "IPv4: ${GREEN}$ip4${NC}"
    echo -e "IPv6: ${GREEN}$ip6${NC}"

    # --- Footer ---
    echo "---------------------------------------------------"
    echo -e "${YELLOW}End of report.${NC}"
}

# ------------------------------------------------------------------------------
#   NAVIGATION
# ------------------------------------------------------------------------------

# Quick navigation one level up
alias ..='cd ..'
alias ...='cd ../..'

# Enter a directory and immediately list its contents
# Usage: cls <directory>
cls() {
    if [ -z "$1" ]; then
        echo "Usage: cls <directory>"
        return 1
    fi
    cd "$1" && ls -F
}

# Create a directory and move into it
# Usage: mkcd <directory>
mkcd() {
    if [ -z "$1" ]; then
        echo "Usage: mkcd <directory>"
        return 1
    fi
    mkdir -p "$1" && cd "$1"
}

# Moves up a specified number of levels (e.g., 'up 3')
# Example:
#   up 3  -> ../../..
# Defaults to one level.
up() {
    local n=${1:-1}
    local path=""
    # Building the path by appending strings - cleaner than stripping slashes later.
    for ((i=0; i<n; i++)); do
        path+="../"
    done
    cd "$path" || return
}

# ------------------------------------------------------------------------------
# FILES & SEARCH
# ------------------------------------------------------------------------------
#
# This section contains aliases and helper functions for:
#   - Listing files with details and hidden files
#   - Searching for files or text inside files
#   - Quick history search
#   - File operations: make executable, copy with progress, backup, create scripts
# ------------------------------------------------------------------------------
# More informative file listing (long format, hidden files, file types)
alias ll='ls -alF'
alias la='ls -A'

# Colored grep output (highlights matches)
alias grep='grep --color=auto'

# Find a file by name in the current directory and subdirectories
# Usage: ffile my_script.py
alias ffile='find . -name'

# Search for text inside files in the current directory and subdirectories
# Usage: ftext "404 error"
alias ftext='grep -rnw . -e'

# Quick search through command history
# Usage: hg docker
alias hg='history | grep'

# Make a file executable
# Usage: mx script.sh
alias mx='chmod +x'

# Count files in the current directory
# Usage: count
count() {
    echo -n "Files in current directory: "
    ls -1 | wc -l
}

# Copy files with progress output (recommended replacement for cp)
# Usage: cpv <source> <destination>
cpv() {
    if [ $# -ne 2 ]; then
        echo "Usage: cpv <source> <destination>"
        return 1
    fi
    rsync -ah --info=progress2 --no-i-r "$1" "$2"
}

# Create a timestamped backup copy of a file
# Usage: bak /etc/fstab
# Result: fstab_20231025_123055.bak
bak() {
    if [ ! -f "$1" ]; then
        echo "Error: '$1' is not a regular file or does not exist."
        return 1
    fi

    local ts
    ts=$(date +%Y%m%d_%H%M%S)

    cp "$1" "$1_$ts.bak" && echo "Backup created: $1_$ts.bak"
}

# Quickly create a shell script
# Creates the file, makes it executable, and inserts a shebang
# Usage: mkscript myscript.sh
mkscript() {
    if [ -z "$1" ]; then
        echo "Usage: mkscript <script_name>"
        return 1
    fi

    echo '#!/bin/bash' > "$1"
    chmod +x "$1"
    nano "$1"
}

# ------------------------------------------------------------------------------
# REMOVABLE STORAGE
# ------------------------------------------------------------------------------
#
# This section provides aliases and functions for working with external drives:
#   - Copy files safely to removable media
#   - Eject safely
#   - Sync and unmount all removable drives for the current user
# ------------------------------------------------------------------------------
# Copy file to external drives (preserves attributes, shows progress)
# Usage: copy source destination
alias copy='rsync -ahW --progress --inplace'

# Alias for safe eject of a device
# Usage: eject /run/media/user/FLASH
alias eject='sync && udisksctl unmount -b'

# Unmount all removable drives mounted under the user's media directory
# WARNING:
#  - This only targets /run/media/$USER by default
#  - Adjust the path if your media is mounted elsewhere
unmount_flash() {
    local media_root="/run/media/$USER"
    
    # Check if the media directory exists
    [ ! -d "$media_root" ] && { echo "No media directory for user $USER found."; return 0; }

    echo "Forcing cache sync..."
    sync
    
    # Find all mounted targets under media_root
    findmnt -runo TARGET | grep "$media_root" | while IFS= read -r mnt; do
        [ -z "$mnt" ] && continue
        echo "Unmounting: $mnt"
        
        # Try to unmount via gio first (GNOME), fallback to udisksctl
        gio mount -u "$mnt" 2>/dev/null || \
        udisksctl unmount -b "$(findmnt -nvo SOURCE "$mnt")"
    done
    
    echo "Done. All drives in $media_root processed."
}

# ------------------------------------------------------------------------------
# ARCHIVES
# ------------------------------------------------------------------------------
#
# This section provides aliases and functions for working with archives:
#   - Extracting various archive types
#   - Creating tar.gz archives
#   - Creating anonymized .tar.xz archives with fixed metadata
# ------------------------------------------------------------------------------
# Extract a tar archive
# Usage: untar archive.tar
alias untar='tar -xvf'

# Create a tar.gz archive from a directory or file
# Usage: mktar <directory_or_file>
mktar() {
    if [ -z "$1" ]; then
        echo "Error: Please specify a file or directory to archive."
        echo "Usage: mktar <directory_or_file>"
        return 1
    fi

    # Remove trailing slash if present
    local name="${1%/}"

    echo "Creating archive '${name}.tar.gz'..."
    tar -czvf "${name}.tar.gz" "$1"
}

# Extract archives based on file extension
# Usage: ex archive.tar.gz
ex() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2)   tar xjf "$1" ;;
            *.tar.gz)    tar xzf "$1" ;;
            *.bz2)       bunzip2 "$1" ;;
            *.rar)       unrar x "$1" ;;
            *.gz)        gunzip "$1" ;;
            *.tar)       tar xf "$1" ;;
            *.tbz2)      tar xjf "$1" ;;
            *.tgz)       tar xzf "$1" ;;
            *.zip)       unzip "$1" ;;
            *.Z)         uncompress "$1" ;;
            *.7z)        7z x "$1" ;;
            *)           echo "Error: '$1' cannot be extracted with ex()" ;;
        esac
    else
        echo "Error: '$1' is not a valid file."
    fi
}

# Anonymous archive creation
# Creates a .tar.xz archive with normalized metadata
# Usage: anon <file_or_directory>
anon() {
    if [ -z "$1" ]; then
        echo "Error: Please specify a file or directory."
        return 1
    fi

    local name="${1%/}"

    echo "Creating anonymized archive '${name}.tar.xz'..."

    # XZ_OPT=-9e enables maximum compression
    # -J switches tar to xz mode
    # --owner/--group reset ownership
    # --mtime sets a fixed timestamp for reproducibility
    XZ_OPT=-9e tar \
        --owner=0 \
        --group=0 \
        --mtime='1997-10-14 00:00Z' \
        -cJvf "${name}.tar.xz" "$1"

    echo "Done. Archive created with normalized metadata."
}

# ------------------------------------------------------------------------------
# MONITORING & RESOURCES
# ------------------------------------------------------------------------------
#
# This section provides aliases and functions for monitoring system resources:
#   - Disk and memory usage
#   - Top CPU and RAM consuming processes
#   - Critical system errors
#   - Process tree visualization
# ------------------------------------------------------------------------------
# Show sizes of directories in the current directory (1 level deep)
# Usage: dud
alias dud='du -h --max-depth=1'

# Show free memory in megabytes
# Usage: mem
alias mem='free -m -l -t'

# Show top 10 memory-consuming processes
# Usage: memtop
alias memtop='ps auxf | sort -nr -k 4 | head -10'

# Show top 10 CPU-consuming processes
# Usage: cputop
alias cputop='ps auxf | sort -nr -k 3 | head -10'

# Show disk usage for physical devices only (ignore tmpfs)
# Usage: disk
alias disk='df -h | grep "^/dev"'

# Show recent critical system errors (priority 3) from systemd journal
# Usage: errors
errors() {
    sudo journalctl -p 3 -xb
}

# Display process tree with PIDs, use 'q' to quit
# Usage: ptree
alias ptree='pstree -p | less'

# ------------------------------------------------------------------------------
#   NETWORK / NETWORK UTILITIES
# ------------------------------------------------------------------------------
# This section contains aliases and functions for quick network analysis, 
# running a local web server, checking ports, scanning the LAN, 
# and monitoring Wi-Fi status. Outputs are colorized and informative.
#
# Usage examples:
#   myip                → shows your external IPv4 address
#   ports               → lists all open listening ports and their processes
#   pingg               → pings google.com 5 times
#   serve 8080          → starts a local HTTP server on port 8080
#   port 22             → shows which process is listening on port 22
#   retry ping -c1 8.8.8.8 → repeats the command until it succeeds
#   net_radar           → scans the local /24 subnet and lists devices
#   net_watchdog        → audits listening services and firewall exposure
#   wifi_history        → shows current Wi-Fi status and last 24h disconnects


# Show external IP address
alias myip='curl ifconfig.me'

# Show all open listening ports
alias ports='sudo ss -tulpn'

# Quick ping to check internet connectivity
alias pingg='ping -c 5 google.com'

# Simple local web server from the current directory
# Usage: serve [port]
serve() {
    local port="${1:-8000}"
    # Detect local IP address to display a usable URL
    local ip
    ip=$(hostname -I | awk '{print $1}')

    echo "Server started at: http://$ip:$port"
    python3 -m http.server "$port"
}

# Show which process is using a specific port
# Usage: port 8080
port() {
    if [ -z "$1" ]; then
        echo "Usage: port <port_number>"
        return 1
    fi
    sudo lsof -i :"$1"
}

# Retry a command until it succeeds
# Repeats the command every 3 seconds
# Examples:
#   retry ping -c 1 google.com
#   retry sudo dnf upgrade
retry() {
    until "$@"; do
        echo "Command failed. Retrying in 3 seconds..."
        sleep 3
    done
    echo "Success."
}

# NETWORK RADAR (net_radar)
# Scans the local network, finds active devices and shows their IP addresses
# and, if available, MAC address vendors.
# Requires nmap: sudo dnf install nmap
net_radar() {
    echo "Determining subnet..."

    # Get the global IPv4 address (e.g. 192.168.1.5/24)
    local my_ip
    my_ip=$(ip -o -4 addr show scope global | awk '{print $4}' | head -n 1)

    if [ -z "$my_ip" ]; then
        echo "Error: No global IP address found. Check network connectivity."
        return 1
    fi

    # Convert to /24 subnet (e.g. 192.168.1.0/24)
    local subnet="${my_ip%.*}.0/24"

    echo "Scanning subnet $subnet..."
    # -sn : Ping scan (no port scanning)
    sudo nmap -sn "$subnet" | grep -B 2 "MAC Address"
}

# NETWORK WATCHDOG (SS + PS + FIREWALLD) (net_watchdog)
# ------------------------------------------------------------------------------
# Audits listening network services, maps them to running processes,
# and checks firewall exposure.
net_watchdog() {
    echo -e "\033[1;34m=== NETWORK SERVICES AUDIT (External) ===\033[0m"
    printf "%-10s %-20s %-15s %-10s %-15s\n" "PORT" "SERVICE (PID)" "USER" "RAM(MB)" "FIREWALL"
    echo "---------------------------------------------------------------------------"

    # Filters applied:
    # 1. Exclude 127.0.0.* (local-only services)
    # 2. Exclude IPv6 loopback [::1]
    # 3. Normalize tcp6/udp6 wildcard addresses

    sudo ss -tulpnH | grep LISTEN | grep -v "127.0.0." | grep -v "\[::1\]" | while read -r line; do

        # Parse socket and port
        local raw_socket
        raw_socket=$(echo "$line" | awk '{print $5}')
        local port="${raw_socket##*:}"

        # Parse PID and process name
        local raw_pid
        raw_pid=$(echo "$line" | awk '{print $7}')
        local pid
        pid=$(echo "$raw_pid" | sed -E 's/.*pid=([0-9]+).*/\1/')
        local proc_name
        proc_name=$(echo "$raw_pid" | sed -E 's/.*"([^"]+)".*/\1/')

        # Skip known local-only helpers
        if [[ "$proc_name" == "passimd" ]]; then
            continue
        fi

        # Process details
        local user="-"
        local ram="-"
        if [[ "$pid" =~ ^[0-9]+$ ]]; then
            user=$(ps -o user= -p "$pid" 2>/dev/null)
            local ram_kb
            ram_kb=$(ps -o rss= -p "$pid" 2>/dev/null)
            ram="$((ram_kb / 1024)) MB"
        fi

        # Firewall status (default: closed)
        local fw_status="\033[0;31mCLOSED\033[0m"

        # Service name normalization
        local check_name="$proc_name"
        if [[ "$proc_name" == "sshd" ]]; then
            check_name="ssh"
        fi

        # Special handling for VPN services
        if [[ "$proc_name" == "tailscaled" ]]; then
            fw_status="\033[1;33mVPN (NAT)\033[0m"
        elif sudo firewall-cmd --list-ports 2>/dev/null | grep -qw "${port}"; then
            fw_status="\033[0;32mOPEN (Port)\033[0m"
        elif sudo firewall-cmd --list-services 2>/dev/null | grep -qw "${check_name}"; then
            fw_status="\033[0;32mOPEN (Service)\033[0m"
        fi

        printf "%-10s %-20s %-15s %-10s %-15b\n" \
            "$port" \
            "${proc_name:0:15} ($pid)" \
            "${user:0:10}" \
            "$ram" \
            "$fw_status"
    done

    echo "---------------------------------------------------------------------------"
}

# WIFI INVESTIGATOR (NMCLI + JOURNALCTL)
# Shows current Wi-Fi status and connection drop history for the last 24 hours
wifi_history() {
    echo -e "\033[1;36m=== WI-FI STATUS & HISTORY ===\033[0m"

    # 1. Current Wi-Fi status via nmcli
    local active_con
    active_con=$(nmcli -t -f NAME,DEVICE,TYPE connection show --active | grep wifi | head -1)

    if [ -z "$active_con" ]; then
        echo -e "Status: \033[0;31mWi-Fi not connected\033[0m"
    else
        local ssid iface
        ssid=$(echo "$active_con" | cut -d':' -f1)
        iface=$(echo "$active_con" | cut -d':' -f2)

        # Extract signal strength, bars and link rate
        local signal rate
        signal=$(nmcli -f IN-USE,SSID,BARS,SIGNAL dev wifi | grep "*" | awk '{print $4 " (" $3 ")"}')
        rate=$(nmcli -f IN-USE,SSID,RATE dev wifi | grep "*" | awk '{$1=$2=""; print $0}' | xargs)

        echo -e "Network:   \033[1;32m$ssid\033[0m"
        echo -e "Interface: $iface"
        echo -e "Signal:    $signal"
        echo -e "Rate:      $rate"
    fi

    echo ""
    echo -e "\033[1;33m[!] Connection drops and reconnects (last 24h):\033[0m"
    echo "--------------------------------------------------------"

    # 2. Log analysis via NetworkManager journal
    # Looking for disconnects, reconnects and roaming events
    journalctl -u NetworkManager --since "24 hours ago" --no-pager | \
        grep -E "(deactivated successfully|reason=|roam to)" | \
        grep -v "reason='now-managed'" | \
        tail -n 10 | \
        while read -r line; do
            # Highlight timestamp
            local time msg
            time=$(echo "$line" | awk '{print $1, $2, $3}')
            msg=$(echo "$line" | cut -d':' -f4-)
            echo -e "\033[0;37m$time\033[0m : $msg"
        done

    echo "--------------------------------------------------------"
}

# ------------------------------------------------------------------------------
#   USEFUL TOOLS
# ------------------------------------------------------------------------------

# Quick note-taking function
# Adds a note to ~/Documents/BashNotes/notes.txt
# Usage:
#   note "Buy milk"         -> adds a new note
#   note                    -> shows last 20 notes
note() {
    local NOTE_FILE="$HOME/Documents/BashNotes/notes.txt"
    local TAIL_LINES=20
    local YELLOW='\033[1;33m'
    local RED='\033[0;31m'
    local NC='\033[0m'

    usage() {
        echo -e "${YELLOW}Usage:${NC}"
        echo "  note                  # show last $TAIL_LINES notes"
        echo "  note \"text\"           # add a new note"
        echo "  note -s PATTERN       # search notes ignoring timestamp"
        echo "  note -e N TEXT        # edit note number N (keep timestamp)"
        echo "  note -d N             # delete note number N"
    }

    backup() {
        [ -f "$NOTE_FILE" ] && cp "$NOTE_FILE" "$NOTE_FILE.$(date +%Y%m%d_%H%M%S).bak"
    }

    mkdir -p "$(dirname "$NOTE_FILE")"
    [ ! -f "$NOTE_FILE" ] && touch "$NOTE_FILE"

    if [ $# -eq 0 ]; then
        [ ! -s "$NOTE_FILE" ] && { echo "No notes yet."; return; }
        tail -n $TAIL_LINES "$NOTE_FILE" | nl -w2 -s'. '
        return
    fi

    case "$1" in
        --help|-h) usage ;;

        -s|--search)
            shift
            local pattern="$*"
            [ -z "$pattern" ] && { echo -e "${RED}Error: no search pattern.${NC}"; return 1; }
            awk '{match($0, /^\[[^]]*\] (.*)$/, arr); line=arr[1]; if (line ~ /'"$pattern"'/) print $0}' "$NOTE_FILE" | nl -w2 -s'. ' | grep --color=always "$pattern" | less -R
            [ ${PIPESTATUS[0]} -eq 0 ] || echo "No matches found for '$pattern'."
            ;;

        -e|--edit)
            shift
            local lineno="$1"; shift
            local new_text="$*"
            [[ ! "$lineno" =~ ^[0-9]+$ ]] && { echo -e "${RED}Error: invalid line number.${NC}"; return 1; }
            [ -z "$new_text" ] && { echo -e "${RED}Error: no text provided.${NC}"; return 1; }

            backup
            sed -i "${lineno}s|^\(\[[^]]*\]\).*|\1 $new_text|" "$NOTE_FILE"
            echo "Edited note $lineno."
            ;;

        -d|--delete)
            shift
            local lineno="$1"
            [[ ! "$lineno" =~ ^[0-9]+$ ]] && { echo -e "${RED}Error: invalid line number.${NC}"; return 1; }

            backup
            sed -i "${lineno}d" "$NOTE_FILE"
            echo "Deleted note $lineno."
            ;;

        *)
            echo "[$(date '+%Y-%m-%d %H:%M')] $*" >> "$NOTE_FILE"
            echo "Added note."
            ;;
    esac
}

# Show weather forecast in terminal
# Usage: weather [city]
weather() {
    if [ -z "$1" ]; then
        curl wttr.in
    else
        curl wttr.in/"$1"
    fi
}

# Cheat.sh helper with highlighting
# Usage:
#   cheat tar          -> shows examples of tar
#   cheat python list  -> shows Python basics
cheat() {
    local query="$*"
    if [ -z "$query" ]; then
        echo "Usage: cheat <topic>"
        return 1
    fi

    local content
    content=$(curl -s "https://cheat.sh/$query")
    content=$(echo "$content" | sed 's/\x1B\[[0-9;]*[mK]//g')

    local yellow='\033[1;33m'
    local nc='\033[0m'
    for word in $query; do
        local safe_word
        safe_word=$(printf '%s\n' "$word" | sed 's/[][()\.^$*?+{}|]/\\&/g')
        content=$(echo "$content" | perl -pe "s/($safe_word)/$yellow\$1$nc/ig")
    done

    echo "$content" | less -R
}

# --- SIMPLE PASSWORD GENERATOR ---
# genpass(length): generates a human-readable secure password
# Usage:
#   genpass          -> 16-char password
#   genpass 20       -> 20-char password
genpass () {
    local length="${1:-16}"
    if ! [[ "$length" =~ ^[0-9]+$ ]] || [ "$length" -le 0 ]; then
        echo "Error: invalid length."
        return 1
    fi

    local chars="abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%^&*"
    local pass=""
    for ((i=0;i<length;i++)); do
        pass+="${chars:RANDOM%${#chars}:1}"
    done

    echo "Your password:"
    echo "$pass"
    echo ""
}

# --- TIMER ---
# Usage: timer 300     -> wait 300 seconds
#        timer 5m      -> wait 5 minutes
#        timer 1h      -> wait 1 hour
timer() {
    local N=$1
    if [ -z "$N" ]; then
        echo "Usage: timer <seconds> (or 5m, 1h)"
        return 1
    fi

    if [[ "$N" == *m ]]; then
        local num="${N%m}"
        [[ "$num" =~ ^[0-9]+$ ]] || { echo "Error: invalid minutes"; return 1; }
        N=$((num * 60))
    elif [[ "$N" == *h ]]; then
        local num="${N%h}"
        [[ "$num" =~ ^[0-9]+$ ]] || { echo "Error: invalid hours"; return 1; }
        N=$((num * 3600))
    fi

    if ! [[ "$N" =~ ^[0-9]+$ ]] || [ "$N" -le 0 ]; then
        echo "Error: invalid or non-positive time."
        return 1
    fi

    echo "Timer started for $N seconds..."
    sleep "$N"
    echo -e "\n⏰ TIME'S UP! ⏰"
    local sound="/usr/share/sounds/freedesktop/stereo/complete.oga"
    [ -f "$sound" ] && paplay "$sound"
}

# --- WEEK NUMBER ---
# week(): show current ISO week, date range, and progress bar
week() {
    local week_num
    week_num=$(date +%V)

    local monday sunday
    monday=$(date -d "monday this week" +%Y-%m-%d)
    sunday=$(date -d "sunday this week" +%Y-%m-%d)

    local weekday
    weekday=$(date +%u)

    local bar="["
    for ((i=1;i<=7;i++)); do
        if [ "$i" -le "$weekday" ]; then
            bar+="#"
        else
            bar+="-"
        fi
    done
    bar+="]"

    echo "Week $week_num: $monday → $sunday"
    echo "Weekday progress: $bar"
}

# ------------------------------------------------------------------------------
# CLIPBOARD UTILITIES (WAYLAND / FEDORA)
# ------------------------------------------------------------------------------
# Note: On Fedora Wayland, xclip may not work reliably. We use wl-clipboard instead.
# Install: sudo dnf install wl-clipboard
# Provides the following commands:
#   cpy   - copy stdin to clipboard
#   pst   - paste clipboard to stdout
#   cpwd  - copy current working directory to clipboard
#   cclip - copy a string argument directly to clipboard

# Copy stdin to clipboard
# Example: cat file.txt | cpy
cpy() {
    wl-copy
}

# Paste clipboard contents to stdout
# Example: pst > file.txt
# Optionally, use -n to strip the final newline
pst() {
    if [ "$1" == "-n" ]; then
        wl-paste -n
    else
        wl-paste
    fi
}

# Copy current working directory to clipboard
# Example: cpwd
cpwd() {
    local dir
    dir="$(pwd)"
    echo -n "$dir" | wl-copy
    echo "Path copied to clipboard: $dir"
}

# Copy a string argument directly to clipboard
# Example: cclip "Hello World"
cclip() {
    if [ -z "$1" ]; then
        echo "Usage: cclip <string>"
        return 1
    fi
    echo -n "$*" | wl-copy
    echo "Copied to clipboard: $*"
}
