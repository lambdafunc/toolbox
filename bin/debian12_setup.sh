#!/usr/bin/env bash
# devops-bootstrap.sh
# Basic DevOps/sysadmin/network tooling for Debian 12

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Please run as root (e.g. sudo $0)" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "[*] Updating package index..."
apt-get update -y

echo "[*] Upgrading existing packages (optional, comment out if not wanted)..."
apt-get dist-upgrade -y

echo "[*] Installing core shell, editors, and utilities..."
apt-get install -y \
  zsh fzf ripgrep fd-find bat tmux \
  vim neovim nano \
  plocate tree p7zip-full zip unzip \
  inxi lshw pciutils usbutils

echo "[*] Installing core sysadmin / troubleshooting tools..."
apt-get install -y \
  htop btop glances iotop iftop dstat sysstat \
  strace ltrace gdb \
  nvme-cli smartmontools lvm2 mdadm \
  gparted parted xfsprogs btrfs-progs \
  build-essential git git-lfs cmake pkg-config dpkg-dev devscripts

echo "[*] Installing networking and security tools..."
apt-get install -y \
  net-tools ethtool bridge-utils vlan \
  mtr-tiny traceroute nmap tcpdump tshark whois \
  dnsutils ldnsutils \
  nftables iptables-nft ufw \
  iw wireless-tools network-manager \
  fail2ban clamav clamav-freshclam lynis \
  openssh-server

echo "[*] Installing DevOps-related tools (some may require extra repos for latest versions)..."
apt-get install -y \
  jq \
  curl wget httpie \
  ansible \
  docker.io \
  rsync screen mosh

echo "[*] Installing Debian-specific helpers..."
apt-get install -y \
  debian-goodies needrestart sudo aptitude \
  manpages manpages-dev

echo "[*] Cleaning up..."
apt-get autoremove -y
apt-get clean

echo "[*] All done. Consider changing your default shell to zsh:"
echo "    chsh -s /usr/bin/zsh \$USER"
