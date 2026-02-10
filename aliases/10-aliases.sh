# ==============================================================================
#   .bash_aliases - PERVERSIONS, DARKNESS, AND DEATH (FEDORA EDITION)
# ==============================================================================

# ------------------------------------------------------------------------------
#   SYSTEM AND UPDATES (DNF ver.)
# ------------------------------------------------------------------------------

# Check and install updates
alias update='sudo dnf upgrade --refresh'

# Update everything + clean the system's "hind chakra"
# --refresh forces metadata update, clean all clears dnf cache
alias upall='sudo dnf upgrade --refresh -y && flatpak update -y && sudo dnf autoremove -y && sudo dnf clean all'

# Quick install
alias inst='sudo dnf install'

# Remove program
alias uninst='sudo dnf remove'

# System cleanup
alias clean='sudo dnf autoremove && sudo dnf clean all'

# Re-run the last command with sudo
# I hope nobody finds out...
alias suka='sudo $(history -p !!)'

# Clear screen
alias c='clear'

# Reload settings
alias reload='source ~/.bashrc; echo "Terminal settings are all set!"'

# Quick power off and reboot
alias off='sudo shutdown -h now'
alias reboot='sudo reboot'

# SYSTEM REPORT
# sysrep — Paranoid health report
# Summarizes memory usage, systemd errors, last logins, and disk space with color coding.
sysrep() {
    local RED='\033[0;31m'
    local GREEN='\033[0;32m'
    local YELLOW='\033[1;33m'
    local NC='\033[0m'

    echo -e "${YELLOW}=== SYSTEM ANALYSIS: $(hostname) ===${NC}"
    echo -e "Time: $(date)"
    echo "---------------------------------------------------"

    echo -e "${GREEN}[1] Load Average:${NC}"
    uptime
    echo ""

    echo -e "${GREEN}[2] RAM Usage:${NC}"
    free -h | grep "Mem:"
    echo ""

    echo -e "${GREEN}[3] Disk Space (/):${NC}"
    df -h / | awk 'NR==2 {if ($5+0 > 90) print "\033[0;31m" $0 "\033[0m"; else print $0}'
    echo ""

    echo -e "${GREEN}[4] Failed Units (Systemd):${NC}"
    local failed=$(systemctl list-units --state=failed --no-legend)
    if [ -z "$failed" ]; then
        echo "All clean. No mysterious disasters detected."
    else
        echo -e "${RED}$failed${NC}"
    fi
    echo ""

    echo -e "${GREEN}[5] Last Logins:${NC}"
    last -n 5 -a | head -n 5
    echo ""

    echo -e "${GREEN}[6] External IP:${NC}"
    local ip4=$(curl -4 -s --connect-timeout 2 ifconfig.me)
    local ip6=$(curl -6 -s --connect-timeout 2 ifconfig.me)
    [ -n "$ip4" ] && echo "IPv4: $ip4" || echo "IPv4: Not detected"
    [ -n "$ip6" ] && echo "IPv6: $ip6" || echo "IPv6: Not detected"
    
    echo -e "\n---------------------------------------------------"
    echo -e "${YELLOW}End of report.${NC}"
}

# ------------------------------------------------------------------------------
#   NAVIGATION
# ------------------------------------------------------------------------------

alias ..='cd ..'
alias ...='cd ../..'

# Enter directory and list contents
cls() {
    cd "$1" && ls -F
}

# Create and enter directory
mkcd() {
    mkdir -p "$1" && cd "$1"
}

# Move up N levels
up() {
    local d=""
    local limit=$1
    for ((i=1 ; i <= ${limit:-1} ; i++))
    do
        d=$d/..
    done
    d=$(echo $d | sed 's/^\///')
    if [ -z "$d" ]; then d=..; fi
    cd $d
}

# ------------------------------------------------------------------------------
#   FILES AND SEARCHING
# ------------------------------------------------------------------------------

alias ll='ls -alF'
alias la='ls -A'
alias grep='grep --color=auto'

# Find file by name
alias ffile='find . -name'

# Find text inside files
alias ftext='grep -rnw . -e'

# Search command history
alias hg='history | grep'

# Make executable
alias mx='chmod +x'

# Count files in current folder
count() {
    echo -n "Files in current folder: "
    ls -1 | wc -l
}

# Rsync-based copy with progress
cpv() {
    rsync -ah --info=progress2 --no-i-r "$1" "$2"
}

# Create timestamped backup
bak() {
    cp "$1" "$1_$(date +%Y%m%d_%H%M%S).bak" && echo "Backup created: $1_$(date +%Y%m%d_%H%M%S).bak"
}

# Quick script creation with Shebang
mkscript() {
    if [ -z "$1" ]; then
        echo "Usage: mkscript <filename.sh>"
        return 1
    fi
    echo '#!/bin/bash' > "$1"
    chmod +x "$1"
    nano "$1"
}

# ------------------------------------------------------------------------------
#   EXTERNAL STORAGE
# ------------------------------------------------------------------------------

alias copy='rsync -ahW --progress --inplace'
alias eject='sync && udisksctl unmount -b'

# Safely unmount all USB drives in /run/media/
unmount_flash() {
    echo "1. Forcing cache flush (sync)..."
    sync
    MOUNT_POINTS=$(mount | grep "/run/media/$USER" | awk '{print $3}')
    if [ -z "$MOUNT_POINTS" ]; then
        echo "No drives found in /run/media/$USER"
        return
    fi
    for mnt in $MOUNT_POINTS; do
        echo "Disconnecting: $mnt"
        gio mount -u "$mnt" 2>/dev/null || udisksctl unmount -b $( findmnt -nvo SOURCE "$mnt" )
    done
    echo "Done! You can now safely remove the drive."
}

# ------------------------------------------------------------------------------
#   ARCHIVES
# ------------------------------------------------------------------------------

alias untar='tar -xvf'

# Archive directory to tar.gz
mktar() {
    if [ -z "$1" ]; then
        echo "Usage: mktar <folder_name>"
        return 1
    fi
    local name="${1%/}"
    echo "Packing '$1' into '$name.tar.gz'..."
    tar -czvf "${name}.tar.gz" "$1"
}

# Smart extraction based on extension
ex () {
  if [ -f "$1" ] ; then
    case "$1" in
      *.tar.bz2)   tar xjf "$1"   ;;
      *.tar.gz)    tar xzf "$1"   ;;
      *.bz2)       bunzip2 "$1"   ;;
      *.rar)       unrar x "$1"   ;;
      *.gz)        gunzip "$1"    ;;
      *.tar)       tar xf "$1"    ;;
      *.tbz2)      tar xjf "$1"   ;;
      *.tgz)       tar xzf "$1"   ;;
      *.zip)       unzip "$1"     ;;
      *.7z)        7z x "$1"      ;;
      *)           echo "'$1' cannot be extracted via ex()" ;;
    esac
  else
    echo "'$1' is not a valid file"
  fi
}

# Anonymous archiving.
# Spoofs the creation date to Unix Epoch (1970-01-01) and removes ownership.
anon() {
    if [ -z "$1" ]; then
        echo "Usage: anon <filename>"
        return 1
    fi
    local name="${1%/}"
    echo "Packing '$1' into .tar.xz with max compression and Unix Epoch timestamp..."
    XZ_OPT=-9e tar --owner=0 --group=0 --mtime='1970-01-01 00:00Z' -cJvf "${name}.tar.xz" "$1"
    echo "Done. Compressed and anonymized."
}

# ------------------------------------------------------------------------------
#   MONITORING
# ------------------------------------------------------------------------------

alias du='du -h --max-depth=1'
alias mem='free -m -l -t'
alias memtop='ps auxf | sort -nr -k 4 | head -10'
alias cputop='ps auxf | sort -nr -k 3 | head -10'
alias disk='df -h | grep "^/dev"'

# View system errors from journalctl
errors() {
    sudo journalctl -p 3 -xb
}

# Process tree
alias ptree='pstree -p | less'

# ------------------------------------------------------------------------------
#   NETWORKING
# ------------------------------------------------------------------------------

alias myip='curl ifconfig.me'
alias ports='sudo ss -tulpn'
alias pingg='ping -c 5 google.com'

# Serve current directory over HTTP
serve() {
    local port="${1:-8000}"
    local ip=$(hostname -I | awk '{print $1}')
    echo "Server running at: http://$ip:$port"
    python3 -m http.server "$port"
}

# Get IP info
ipinfo() {
    curl ipinfo.io/"$1"
}

# Check which process is using a port
port() {
    sudo lsof -i :"$1"
}

# Retry command until success
retry() {
    until "$@"; do
        echo "Failed. Retrying in 3 seconds..."
        sleep 3
    done
    echo "Success!"
}

# Scan local network
net_radar() {
    local my_ip=$(ip -o -4 addr list | grep -v "127.0.0.1" | head -n1 | awk '{print $4}')
    if [ -z "$my_ip" ]; then
        echo "Unable to detect IP."
        return 1
    fi
    echo "Scanning $my_ip..."
    sudo nmap -sn "$my_ip" | grep -B 2 "MAC Address"
}

# Audit external network services and firewall status
net_watchdog() {
    echo -e "\033[1;34m=== NETWORK SERVICE AUDIT (External) ===\033[0m"
    printf "%-10s %-20s %-15s %-10s %-15s\n" "PORT" "SERVICE (PID)" "USER" "RAM(MB)" "FIREWALL"
    echo "---------------------------------------------------------------------------"
    sudo ss -tulpnH | grep LISTEN | grep -v "127.0.0." | grep -v "\[::1\]" | while read -r line ; do
        local raw_socket=$(echo "$line" | awk '{print $5}')
        local port="${raw_socket##*:}"
        local raw_pid=$(echo "$line" | awk '{print $7}')
        local pid=$(echo "$raw_pid" | sed -E 's/.*pid=([0-9]+).*/\1/')
        local proc_name=$(echo "$raw_pid" | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ "$proc_name" == "passimd" ]]; then continue; fi
        local user="-"
        local ram="-"
        if [[ "$pid" =~ ^[0-9]+$ ]]; then
            user=$(ps -o user= -p "$pid" 2>/dev/null)
            local ram_kb=$(ps -o rss= -p "$pid" 2>/dev/null)
            ram="$((ram_kb / 1024)) MB"
        fi
        local fw_status="\033[0;31mCLOSED\033[0m" 
        local check_name="$proc_name"
        if [[ "$proc_name" == "sshd" ]]; then check_name="ssh"; fi
        if [[ "$proc_name" == "tailscaled" ]]; then
            fw_status="\033[1;33mVPN (NAT)\033[0m"
        elif sudo firewall-cmd --list-ports 2>/dev/null | grep -qw "${port}"; then
            fw_status="\033[0;32mOPEN (Port)\033[0m"
        elif sudo firewall-cmd --list-services 2>/dev/null | grep -qw "${check_name}"; then
            fw_status="\033[0;32mOPEN (Svc)\033[0m"
        fi
        printf "%-10s %-20s %-15s %-10s %-15b\n" "$port" "${proc_name:0:15} ($pid)" "${user:0:10}" "$ram" "$fw_status"
    done
}

# ------------------------------------------------------------------------------
#   UTILITIES
# ------------------------------------------------------------------------------

# Save a quick note
note() {
    local NOTES_DIR="$HOME/Documents/BashNotes"
    mkdir -p "$NOTES_DIR"
    local NOTE_FILE="$NOTES_DIR/notes.txt"
    if [ -z "$1" ]; then
        [ -f "$NOTE_FILE" ] && less "$NOTE_FILE" || echo "No notes found."
    else
        echo "[$(date '+%Y-%m-%d %H:%M')] $*" >> "$NOTE_FILE"
        echo "Note saved to: $NOTES_DIR"
    fi
}

weather() {
    [ -z "$1" ] && curl wttr.in || curl wttr.in/"$1"
}

cheat() {
    [ -z "$1" ] && echo "Usage: cheat <topic>" || curl "cheat.sh/$1"
}

# Password generator
genpass() {
    local length="${1:-16}"
    tr -dc 'A-Za-z0-9!@#$%^&*' < /dev/urandom | head -c "$length"
    echo ""
}

# Timer with sound notification
timer() {
    local N=$1
    if [ -z "$N" ]; then echo "Usage: timer <seconds> (or 5m, 1h)"; return; fi
    [[ "$N" =~ "m" ]] && N=$((${N%m} * 60))
    [[ "$N" =~ "h" ]] && N=$((${N%h} * 3600))
    echo "Timer set for $N seconds..."
    sleep "$N" && echo -e "\n⏰ TIME IS UP! ⏰" && paplay /usr/share/sounds/freedesktop/stereo/complete.oga
}

# Python-based calculator
calc() {
    python3 -c "print($*)"
}

alias week='date +%V'

# ------------------------------------------------------------------------------
#   CLIPBOARD (Wayland / Fedora)
# ------------------------------------------------------------------------------

alias cpy='wl-copy'
alias pst='wl-paste'
alias cpwd='pwd | tr -d "\n" | wl-copy && echo "Path copied!"'
