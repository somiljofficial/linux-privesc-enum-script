#!/usr/bin/env bash

# linpriv_enum.sh - quick priv-esc enum script for Linux boxes
# made this while grinding CTFs, got tired of running the same 10 commands
# manually every time so wrapped them into one script.
# checks SUID/SGID bins, sudo -l stuff, cron writability, and loose file perms
#
# only run this on boxes you're actually allowed to test on (CTF/lab/scoped pentest)
# - Somil

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

OUTFILE=""
while getopts "o:h" opt; do
  case "$opt" in
    o) OUTFILE="$OPTARG" ;;
    h) echo "usage: $0 [-o outputfile]"; exit 0 ;;
    *) ;;
  esac
done

# save to file too if -o was passed
if [[ -n "$OUTFILE" ]]; then
  exec > >(tee "$OUTFILE") 2>&1
fi

section() {
  echo -e "\n${BOLD}${CYAN}------------------------------------------------------------${NC}"
  echo -e "${BOLD}${CYAN}[*] $1${NC}"
  echo -e "${BOLD}${CYAN}------------------------------------------------------------${NC}"
}

info()  { echo -e "${YELLOW}[i] $1${NC}"; }
good()  { echo -e "${GREEN}[+] $1${NC}"; }
bad()   { echo -e "${RED}[!] $1${NC}"; }

# quick GTFOBins cross-check list, added the ones i actually run into most.
# full list is at gtfobins.github.io if this misses something
gtfobins="nmap vim find bash sh less more nano cp mv awk perl python python3 ruby lua tar zip gdb tcpdump env socat ftp ssh scp rsync openssl php node xxd git make man"

section "system info"
echo "hostname : $(hostname 2>/dev/null)"
echo "kernel   : $(uname -a 2>/dev/null)"
echo "os       : $(grep -E '^(NAME|VERSION)=' /etc/os-release 2>/dev/null | tr '\n' ' ')"
echo "user     : $(id 2>/dev/null)"

section "SUID / SGID binaries"

info "looking for SUID binaries, might take a sec on bigger filesystems..."
suid_files=$(find / -xdev -perm -4000 -type f 2>/dev/null)
if [[ -z "$suid_files" ]]; then
  info "nothing found, or find got blocked by perms"
else
  echo "$suid_files" | while read -r f; do
    bname=$(basename "$f")
    hit=""
    for g in $gtfobins; do
      if [[ "$bname" == "$g" ]]; then
        hit=" ${RED}<- check gtfobins.github.io/gtfobins/${bname} , this one's often exploitable${NC}"
        break
      fi
    done
    echo -e "  $f$hit"
  done
fi

info "now SGID..."
sgid_files=$(find / -xdev -perm -2000 -type f 2>/dev/null)
if [[ -z "$sgid_files" ]]; then
  info "nothing found here either"
else
  echo "$sgid_files" | sed 's/^/  /'
fi

section "sudo misconfigs"

if command -v sudo >/dev/null 2>&1; then
  info "sudo -l -n output (non-interactive so it won't hang asking for password):"
  sudo_l=$(sudo -l -n 2>&1)
  echo "$sudo_l" | sed 's/^/  /'

  if echo "$sudo_l" | grep -qi "NOPASSWD"; then
    bad "NOPASSWD entries above - can run those as root without a password, check GTFOBins for the binary"
  fi
  if echo "$sudo_l" | grep -qiE "ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL"; then
    bad "looks like full (ALL) sudo rights, easy root if true"
  fi
else
  info "no sudo on this box"
fi

if [[ -f /etc/sudoers ]]; then
  perm=$(stat -c '%a %U:%G' /etc/sudoers 2>/dev/null)
  echo "  /etc/sudoers -> $perm"
  [[ -w /etc/sudoers ]] && bad "/etc/sudoers is writable by us, instant root"
fi

if [[ -d /etc/sudoers.d ]]; then
  w=$(find /etc/sudoers.d -writable -type f 2>/dev/null)
  if [[ -n "$w" ]]; then
    bad "writable files in /etc/sudoers.d:"
    echo "$w" | sed 's/^/  /'
  fi
fi

section "cron jobs"

info "checking the usual cron locations:"
for c in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
  [[ -e "$c" ]] && ls -ld "$c" 2>/dev/null | sed 's/^/  /'
done

info "any cron files we can actually write to?"
cron_writable=$(find /etc/cron* /var/spool/cron* -type f -writable 2>/dev/null)
if [[ -n "$cron_writable" ]]; then
  bad "yep, writable cron files:"
  echo "$cron_writable" | sed 's/^/  /'
else
  info "none writable for current user"
fi

info "dumping /etc/crontab if we can read it:"
[[ -r /etc/crontab ]] && grep -Ev '^\s*#|^\s*$' /etc/crontab 2>/dev/null | sed 's/^/  /'

info "checking if the scripts crontab actually calls are writable (this one's easy to miss manually):"
cron_scripts=$( (cat /etc/crontab 2>/dev/null; cat /etc/cron.d/* 2>/dev/null) | grep -Ev '^\s*#|^\s*$' | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}' | tr ' ' '\n' | grep -E '^(/|\./)' )
if [[ -n "$cron_scripts" ]]; then
  echo "$cron_scripts" | sort -u | while read -r s; do
    [[ -z "$s" ]] && continue
    [[ -w "$s" ]] && bad "cron runs this and we can write to it: $s"
  done
fi

if command -v crontab >/dev/null 2>&1; then
  info "our own crontab (crontab -l):"
  crontab -l 2>/dev/null | sed 's/^/  /' || info "no personal crontab set"
fi

section "loose file permissions"

info "world-writable files (skipping /proc /sys, capping at 100 results):"
find / -xdev \( -path /proc -o -path /sys \) -prune -o -type f -perm -0002 -print 2>/dev/null | head -n 100 | sed 's/^/  /'

info "world-writable dirs with no sticky bit (these are actually dangerous):"
find / -xdev \( -path /proc -o -path /sys \) -prune -o -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -n 50 | sed 's/^/  /'

info "perms on the sensitive files:"
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
  if [[ -e "$f" ]]; then
    p=$(stat -c '%a %U:%G' "$f" 2>/dev/null)
    echo "  $f -> $p"
    [[ -w "$f" ]] && bad "$f is writable, that's basically game over"
  fi
done

info "checking capabilities (setcap privesc, people forget this exists):"
if command -v getcap >/dev/null 2>&1; then
  getcap -r / 2>/dev/null | sed 's/^/  /'
else
  info "getcap isn't installed, skipping"
fi

section "done"
good "enum finished, go through the ${RED}[!]${NC} lines first, those are the real leads"
[[ -n "$OUTFILE" ]] && good "also saved everything to: $OUTFILE"
