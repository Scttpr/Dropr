#!/usr/bin/env bash
# Harden a fresh, single-purpose Debian 13 host for Dropr. Run it once before
# install.sh, and again after editing its options; it is idempotent.
#
#   sudo deploy/debian/harden-host.sh --admin-user alice --admin-cidr 203.0.113.7/32 --dry-run
#   sudo deploy/debian/harden-host.sh --admin-user alice --admin-cidr 203.0.113.7/32
#
# What it sets (each part can be skipped with --skip NAME):
#   sysctl    kernel and network hardening (/etc/sysctl.d/90-dropr-hardening.conf)
#   ssh       key-only logins for the admin users, no root, modern algorithms
#   firewall  nftables: inbound SSH from the admin networks, 80/443, nothing else
#   updates   unattended security upgrades with an automatic reboot window
#   time      chrony with NTS (authenticated time) from several sources
#
# SSH and the firewall are applied together under a guard: unless you confirm
# within two minutes, from a NEW SSH session, that you can still log in, both
# are rolled back. Files it replaces are kept once as <file>.dropr-orig.
# Full guide: docs/deploy-debian.md.
set -euo pipefail

admin_users=()
admin_cidrs=()
nts_servers=()
skip=" "
dry_run=false
assume_yes=false
ssh_anywhere=false
reboot_time=04:00
STATE=/var/backups/dropr-harden-host

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<'EOF'
Options:
  --admin-user USER      may log in over SSH (repeatable; needs authorized_keys and sudo)
  --admin-cidr CIDR      network allowed to reach SSH, IPv4 or IPv6 (repeatable)
  --ssh-from-anywhere    allow SSH from any address, rate-limited, instead of --admin-cidr
  --nts-server HOST      NTS time server (repeatable; default: Cloudflare, Netnod, PTB)
  --reboot-time HH:MM    when unattended upgrades may reboot (default 04:00)
  --skip NAME            skip sysctl, ssh, firewall, updates or time (repeatable)
  --dry-run              show the files that would change; change nothing
  --yes                  do not ask for the SSH confirmation (no rollback guard)
EOF
}

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
want() { [[ $skip != *" $1 "* ]]; }

while [ $# -gt 0 ]; do
  case "$1" in
    --admin-user) admin_users+=("${2:?--admin-user needs a name}"); shift 2 ;;
    --admin-cidr) admin_cidrs+=("${2:?--admin-cidr needs a CIDR}"); shift 2 ;;
    --ssh-from-anywhere) ssh_anywhere=true; shift ;;
    --nts-server) nts_servers+=("${2:?--nts-server needs a host}"); shift 2 ;;
    --reboot-time) reboot_time=${2:?--reboot-time needs HH:MM}; shift 2 ;;
    --skip)
      case "${2:-}" in sysctl|ssh|firewall|updates|time) skip+="$2 " ;; *) die "--skip takes sysctl, ssh, firewall, updates or time" ;; esac
      shift 2 ;;
    --dry-run) dry_run=true; shift ;;
    --yes) assume_yes=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done
[ ${#nts_servers[@]} -gt 0 ] || nts_servers=(time.cloudflare.com nts.netnod.se ptbtime1.ptb.de)

# --- Preflight -----------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "run as root (sudo $0 ...)"
# shellcheck source=/dev/null
. /etc/os-release
[ "${ID:-}" = debian ] && [ "${VERSION_ID%%.*}" -ge 13 ] 2>/dev/null \
  || die "this script targets Debian 13 (found ${PRETTY_NAME:-unknown})"
[[ $reboot_time =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "--reboot-time must be HH:MM"

if want ssh || want firewall; then
  [ ${#admin_users[@]} -gt 0 ] || die "give at least one --admin-user (or --skip ssh --skip firewall)"
  for u in "${admin_users[@]}"; do
    getent passwd "$u" >/dev/null || die "no such user: $u"
    home=$(getent passwd "$u" | cut -d: -f6)
    [ -s "$home/.ssh/authorized_keys" ] || die "$u has no $home/.ssh/authorized_keys: refusing to disable passwords and lock you out"
    id -nG "$u" | tr ' ' '\n' | grep -qx sudo || die "$u is not in the sudo group: with root login disabled you would lose root"
  done
fi
if want firewall; then
  $ssh_anywhere || [ ${#admin_cidrs[@]} -gt 0 ] || die "give --admin-cidr (your admin address or network) or --ssh-from-anywhere"
  for c in "${admin_cidrs[@]}"; do
    [[ $c =~ ^[0-9a-fA-F.:]+(/[0-9]{1,3})?$ ]] || die "not an IP address or CIDR: $c"
  done
  if [ -n "${SSH_CONNECTION:-}" ] && ! $ssh_anywhere; then
    log "This session comes from ${SSH_CONNECTION%% *}: make sure an --admin-cidr covers it"
  fi
fi
$dry_run && log "Dry run: nothing is changed"
mkdir -p "$STATE"
chmod 0700 "$STATE"

# put PATH MODE < content: install the file if it differs (diff in a dry run).
# Sets put_changed (not visible to the caller when put runs in a pipeline).
put_changed=false
put() {
  local path=$1 mode=$2 tmp
  put_changed=false
  tmp=$(mktemp)
  cat > "$tmp"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then rm -f "$tmp"; return 0; fi
  put_changed=true
  if $dry_run; then
    diff -u --label "$path" --label "$path (new)" "$( [ -f "$path" ] && echo "$path" || echo /dev/null)" "$tmp" || true
    rm -f "$tmp"
    return 0
  fi
  [ ! -e "$path" ] || [ -e "$path.dropr-orig" ] || cp -p "$path" "$path.dropr-orig"
  install -D -m "$mode" "$tmp" "$path"
  rm -f "$tmp"
  log "Wrote $path"
}

# --- Packages ------------------------------------------------------------------------
pkgs=(apparmor)
want firewall && pkgs+=(nftables)
want updates && pkgs+=(unattended-upgrades apt-listchanges)
want time && pkgs+=(chrony)
missing=()
for p in "${pkgs[@]}"; do
  dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'ok installed' || missing+=("$p")
done
if [ ${#missing[@]} -gt 0 ]; then
  if $dry_run; then log "Would install: ${missing[*]}"; else
    log "Installing ${missing[*]}"
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" >/dev/null
  fi
fi

# --- sysctl ---------------------------------------------------------------------------
if want sysctl; then
  put /etc/sysctl.d/90-dropr-hardening.conf 0644 <<'EOF'
# Written by deploy/debian/harden-host.sh.
# Kernel: hide kernel pointers and logs, no unprivileged BPF, user namespaces
# or perf, ptrace for root only, no kexec or magic SysRq.
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.unprivileged_userns_clone = 0
kernel.perf_event_paranoid = 3
kernel.yama.ptrace_scope = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
dev.tty.ldisc_autoload = 0
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Network: no redirects or source routing, SYN cookies, log martians.
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
  $dry_run || sysctl -q --system >/dev/null
fi

# --- Unattended upgrades ---------------------------------------------------------------
if want updates; then
  put /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  put /etc/apt/apt.conf.d/52dropr-unattended-upgrades 0644 <<EOF
// Written by deploy/debian/harden-host.sh. Debian's 50unattended-upgrades
// selects the security and stable-update origins; this adds the reboots that
// kernel and libc fixes need. Dropr restarts on boot.
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "$reboot_time";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::SyslogEnable "true";
EOF
fi

# --- Time: chrony with NTS --------------------------------------------------------------
# OIDC client assertions and tokens fail when the clock drifts, and plain NTP
# can be spoofed on the path; NTS authenticates the servers.
if want time; then
  {
    echo "# Written by deploy/debian/harden-host.sh: NTS-authenticated sources only."
    for s in "${nts_servers[@]}"; do echo "server $s iburst nts"; done
  } | put /etc/chrony/sources.d/dropr-nts.sources 0644
  put /etc/chrony/conf.d/dropr.conf 0644 <<'EOF'
# Written by deploy/debian/harden-host.sh: adjust only when two sources agree.
minsources 2
EOF
  if [ -f /etc/chrony/chrony.conf ]; then
    # Drop the unauthenticated pool and DHCP-provided servers.
    sed -E -e 's/^(pool[[:space:]].*)$/# \1  # disabled by harden-host.sh (NTS only)/' \
           -e 's|^(sourcedir[[:space:]]+/run/chrony-dhcp.*)$|# \1  # disabled by harden-host.sh (NTS only)|' \
           /etc/chrony/chrony.conf | put /etc/chrony/chrony.conf 0644
    grep -Eq '^sourcedir[[:space:]]+/etc/chrony/sources.d' /etc/chrony/chrony.conf \
      || $dry_run || die "/etc/chrony/chrony.conf does not read /etc/chrony/sources.d"
  fi
  $dry_run || systemctl restart chrony
fi

# --- SSH and firewall (guarded) ------------------------------------------------------------
guarded=false
if want ssh; then
  sshd_dropin=/etc/ssh/sshd_config.d/10-dropr-hardening.conf
  if [ -e "$sshd_dropin" ]; then cp -p "$sshd_dropin" "$STATE/sshd.prev"; else rm -f "$STATE/sshd.prev"; fi
  # The first value sshd reads wins, so this file (10-) beats cloud-init's 50-.
  put "$sshd_dropin" 0644 <<EOF
# Written by deploy/debian/harden-host.sh.
AllowUsers ${admin_users[*]}
PermitRootLogin no
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
PermitUserEnvironment no
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
EOF
  if $put_changed && ! $dry_run; then
    if ! sshd -t; then
      if [ -e "$STATE/sshd.prev" ]; then cp -p "$STATE/sshd.prev" "$sshd_dropin"; else rm -f "$sshd_dropin"; fi
      die "sshd rejected the configuration; restored the previous one"
    fi
    sshd -T | grep -qx 'passwordauthentication no' || die "sshd still allows passwords: check the Include line in /etc/ssh/sshd_config"
    guarded=true
  fi
fi

if want firewall; then
  v4=() v6=()
  for c in "${admin_cidrs[@]}"; do if [[ $c == *:* ]]; then v6+=("$c"); else v4+=("$c"); fi; done
  join() { local IFS=,; echo "$*"; }
  {
    cat <<'EOF'
#!/usr/sbin/nft -f
# Written by deploy/debian/harden-host.sh. Inbound: SSH from the admin
# networks, HTTP and HTTPS from anywhere, nothing else. Outbound stays open
# (identity provider, Let's Encrypt, NTS, apt, off-site backups).
flush ruleset

table inet filter {
EOF
    if $ssh_anywhere; then
      printf '\tset ssh_rate4 { type ipv4_addr; flags dynamic; timeout 10m; }\n'
      printf '\tset ssh_rate6 { type ipv6_addr; flags dynamic; timeout 10m; }\n\n'
    else
      printf '\tset admin4 {\n\t\ttype ipv4_addr; flags interval;\n'
      [ ${#v4[@]} -eq 0 ] || printf '\t\telements = { %s }\n' "$(join "${v4[@]}")"
      printf '\t}\n\tset admin6 {\n\t\ttype ipv6_addr; flags interval;\n'
      [ ${#v6[@]} -eq 0 ] || printf '\t\telements = { %s }\n' "$(join "${v6[@]}")"
      printf '\t}\n\n'
    fi
    cat <<'EOF'
	chain input {
		type filter hook input priority filter; policy drop;
		ct state established,related accept
		ct state invalid drop
		iif lo accept

		# ICMP errors (path MTU) and IPv6 neighbour discovery are required.
		icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
		icmp type echo-request limit rate 5/second accept
		icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
		icmpv6 type echo-request limit rate 5/second accept
		# DHCP and DHCPv6 replies to this host's client.
		udp sport 67 udp dport 68 accept
		ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept

EOF
    if $ssh_anywhere; then
      printf '\t\ttcp dport 22 ct state new update @ssh_rate4 { ip saddr limit rate over 10/minute burst 10 packets } drop\n'
      printf '\t\ttcp dport 22 ct state new update @ssh_rate6 { ip6 saddr limit rate over 10/minute burst 10 packets } drop\n'
      printf '\t\ttcp dport 22 accept\n'
    else
      printf '\t\ttcp dport 22 ip saddr @admin4 accept\n'
      printf '\t\ttcp dport 22 ip6 saddr @admin6 accept\n'
    fi
    cat <<'EOF'
		tcp dport { 80, 443 } accept
	}

	chain forward {
		type filter hook forward priority filter; policy drop;
	}

	chain output {
		type filter hook output priority filter; policy accept;
	}
}
EOF
  } > "$STATE/nftables.new"
  if $dry_run; then
    put /etc/nftables.conf 0755 < "$STATE/nftables.new"
  else
    nft -c -f "$STATE/nftables.new" || die "nftables rejected the generated rules ($STATE/nftables.new)"
    { echo "flush ruleset"; nft list ruleset; } > "$STATE/ruleset.prev"
    [ -e /etc/nftables.conf ] && cp -p /etc/nftables.conf "$STATE/nftables.conf.prev"
    put /etc/nftables.conf 0755 < "$STATE/nftables.new"
    systemctl enable --quiet nftables
    if $put_changed; then
      nft -f /etc/nftables.conf
      guarded=true
    fi
  fi
fi

if $guarded; then
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  if $assume_yes; then
    log "SSH and firewall applied (--yes: no rollback guard)"
  else
    [ -t 0 ] || die "SSH and firewall changes need a terminal to confirm (or --yes); they are applied but will be rolled back"
    cat > "$STATE/rollback" <<EOF
#!/bin/sh
# Restores the SSH and firewall state from before the last harden-host.sh run.
if [ -e "$STATE/sshd.prev" ]; then cp -p "$STATE/sshd.prev" /etc/ssh/sshd_config.d/10-dropr-hardening.conf
else rm -f /etc/ssh/sshd_config.d/10-dropr-hardening.conf; fi
systemctl reload ssh
if [ -e "$STATE/ruleset.prev" ]; then nft -f "$STATE/ruleset.prev"; fi
if [ -e "$STATE/nftables.conf.prev" ]; then cp -p "$STATE/nftables.conf.prev" /etc/nftables.conf; fi
EOF
    chmod 0700 "$STATE/rollback"
    systemctl stop dropr-harden-rollback.timer 2>/dev/null || true
    systemd-run --quiet --unit=dropr-harden-rollback --on-active=120 "$STATE/rollback"
    log "SSH and firewall applied. Rollback in 120 s unless you confirm."
    echo "    From a NEW terminal, log in again (ssh ${admin_users[0]}@<this host>) and run sudo -v."
    answer=""
    read -r -t 110 -p "    Type 'keep' once that works: " answer || true
    if [ "$answer" = keep ]; then
      systemctl stop dropr-harden-rollback.timer
      log "Kept"
    else
      systemctl stop dropr-harden-rollback.timer 2>/dev/null || true
      "$STATE/rollback"
      die "not confirmed: SSH and firewall rolled back to their previous state"
    fi
  fi
fi

# --- Report ---------------------------------------------------------------------------------
log "Checks"
if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]; then
  echo "    AppArmor: enabled"
else
  warn "AppArmor is disabled: enable it (apparmor=1 security=apparmor on the kernel command line)"
fi
if systemd-creds has-tpm2 >/dev/null 2>&1; then
  echo "    TPM2: present (install.sh seals the secrets to it)"
else
  warn "no TPM2: secrets are sealed to the host key only, so a full disk copy can decrypt them; prefer a host or VM with a (v)TPM"
fi
data=/var/lib/dropr
[ -d "$data" ] || data=/var/lib
opts=$(findmnt -no OPTIONS -T "$data" 2>/dev/null || true)
for o in nodev nosuid noexec; do
  [[ ,$opts, == *,$o,* ]] || { warn "$data is on a mount without nodev,nosuid,noexec; a dedicated mount for /var/lib/dropr is recommended"; break; }
done
if want time && ! $dry_run; then
  echo "    Time sources (NTS needs a minute to show up): chronyc -N authdata"
fi
if $dry_run; then log "Dry run complete"; else log "Host hardened. Next: deploy/debian/install.sh"; fi
