# Linux Privilege Escalation Enumeration Script

A bash script I built for automating the boring recon part of Linux privesc — 
checking SUID/SGID binaries, sudo misconfigs, cron job writability, and loose 
file permissions in one shot instead of running the same 10 commands by hand 
every time.

## What it checks

- **SUID / SGID binaries** — finds all of them and cross-checks against a 
  common GTFOBins list so you know instantly if one's exploitable
- **Sudo misconfigs** — runs `sudo -l -n`, flags NOPASSWD entries and full 
  ALL=(ALL) rights, checks if `/etc/sudoers` or `/etc/sudoers.d/` is writable
- **Cron jobs** — checks writability of crontab, cron.d, cron.daily etc., 
  and (the part people usually miss) whether the *scripts referenced inside* 
  those cron files are writable
- **File permissions** — world-writable files/dirs, missing sticky bits, 
  perms on `/etc/passwd` and `/etc/shadow`, and capabilities via `getcap`

## Usage

```bash
chmod +x linpriv_enum.sh
./linpriv_enum.sh                # prints to terminal
./linpriv_enum.sh -o report.txt  # also saves output to a file
```

## Sample output

Flags high-value findings with `[!]` in red so you don't have to read through 
everything line by line — those are the leads worth chasing first.

## Disclaimer

Built for use on CTF boxes, personal labs, and engagements with proper 
authorization. Don't run this on systems you don't own or don't have 
explicit permission to test.

## Why I built this

Made this while working through CTFs and PortSwigger/TryHackMe boxes — got 
tired of manually running `find / -perm -4000`, `sudo -l`, checking cron 
perms etc. every single time. Wrapped it into one script.
