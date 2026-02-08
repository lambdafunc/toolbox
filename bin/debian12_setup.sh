#!/usr/bin/env bash
# devops-bootstrap.sh
# Basic DevOps/sysadmin/network tooling for Debian 12
# Continues even if some packages fail to install.

set -u  # no -e here; we handle errors per package
set -o pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root (e.g. sudo $0)" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

install_group() {
  local group_name="$1"; shift
  local pkg
  echo
  echo "[*] Installing group: ${group_name}"
  for pkg in "$@"; do
    echo "    - ${pkg}"
    if apt-get install -y "$pkg"; then
      echo "      -> OK"
    else
      echo "      -> FAILED (skipping and continuing)" >&2
    fi
  done
}

echo "[*] Updating package index..."
apt-get update -y

echo "[*] Upgrading existing packages (optional, comment out if not wanted)..."
apt-get dist-upgrade -y || echo "[!] dist-upgrade failed, continuing..." >&2

install_group "Shell, editors, utilities" \
  zsh fzf ripgrep fd-find bat tmux \
  vim neovim nano \
  plocate tree p7zip-full zip unzip \
  inxi lshw pciutils usbutils

install_group "Sysadmin / troubleshooting" \
  htop btop glances iotop iftop dstat sysstat \
  strace ltrace gdb \
  nvme-cli smartmontools lvm2 mdadm \
  gparted parted xfsprogs btrfs-progs \
  build-essential git git-lfs cmake pkg-config dpkg-dev devscripts

install_group "Networking and security" \
  net-tools ethtool bridge-utils vlan \
  mtr-tiny traceroute nmap tcpdump tshark whois \
  dnsutils ldnsutils \
  nftables iptables-nft ufw \
  iw wireless-tools network-manager \
  fail2ban clamav clamav-freshclam lynis \
  openssh-server

install_group "DevOps-related tools" \
  jq \
  curl wget httpie \
  ansible \
  docker.io \
  rsync screen mosh

install_group "Debian helpers" \
  debian-goodies needrestart sudo aptitude \
  manpages manpages-dev

echo
echo "[*] Cleaning up..."
apt-get autoremove -y || echo "[!] autoremove failed, continuing..." >&2
apt-get clean || echo "[!] clean failed, continuing..." >&2

echo
echo "[*] All done. Consider changing your default shell to zsh:"
echo "    chsh -s /usr/bin/zsh \$USER"
