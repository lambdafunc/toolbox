#!/usr/bin/env bash

# Lightweight LAN scanner for macOS/Linux (tested on macOS)
# - Discovers live hosts on a /24 subnet (default 192.168.0.0/24)
# - Resolves hostnames where possible (ARP/DNS/mDNS fallbacks)
# - Scans common TCP ports using nc (or nmap if requested)
#
# Usage examples:
#   sudo ./lan_scan.sh                      # scan 192.168.0.0/24
#   sudo ./lan_scan.sh -s 192.168.1.0/24    # scan specific subnet
#   sudo ./lan_scan.sh --auto               # auto-detect local /24 from default route
#   sudo ./lan_scan.sh -p 22,80,443,3389    # scan custom ports
#   sudo ./lan_scan.sh --nmap               # prefer nmap for discovery/ports if available
#   sudo ./lan_scan.sh -o csv               # CSV output

set -u

SUBNET="192.168.0.0/24"
PORTS="22,80,443,53,139,445,548,631,5353,8000,8080,8443,3389,5432,5900,1883,3306,9100,32400,27017,5000,21,23,25,110,143"
TIMEOUT=1          # seconds for ping connect and nc connect timeout
CONCURRENCY=64     # parallel pings during discovery
FORMAT="text"      # text|csv|json
USE_NMAP=0
AUTO_DETECT=0
INTERFACE=""

usage() {
  cat <<EOF
LAN scanner

Options:
  -s, --subnet CIDR      Subnet to scan (default: ${SUBNET})
                         Accepts "+.prefix" like 192.168.0. as shorthand for /24
  -i, --interface IFACE  Network interface to use with --auto (e.g., en0)
  -p, --ports LIST       Comma-separated TCP ports to scan
  -t, --timeout SEC      Timeout per probe (default: ${TIMEOUT})
  -c, --concurrency N    Concurrent pings during discovery (default: ${CONCURRENCY})
  -o, --output FORMAT    Output: text|csv|json (default: ${FORMAT})
      --nmap             Prefer nmap if available (faster/accurate)
      --auto             Auto-detect /24 from default interface
  -h, --help             Show this help

Examples:
  sudo $0
  sudo $0 -s 192.168.1.0/24
  sudo $0 --auto
  sudo $0 -p 22,80,443 --nmap
EOF
}

# Parse args
while [ $# -gt 0 ]; do
  case "$1" in
    -s|--subnet) SUBNET="$2"; shift 2;;
    -i|--interface) INTERFACE="$2"; shift 2;;
    -p|--ports) PORTS="$2"; shift 2;;
    -t|--timeout) TIMEOUT="$2"; shift 2;;
    -c|--concurrency) CONCURRENCY="$2"; shift 2;;
    -o|--output) FORMAT="$2"; shift 2;;
    --nmap) USE_NMAP=1; shift;;
    --auto) AUTO_DETECT=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Auto-detect a /24 if requested
if [ "$AUTO_DETECT" -eq 1 ]; then
  # Find default interface (macOS)
  if [ -z "$INTERFACE" ]; then
    if command_exists route; then
      INTERFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || true)
    fi
  fi
  if [ -z "$INTERFACE" ]; then
    echo "Could not determine default interface. Use --interface IFACE." >&2
    exit 1
  fi
  # Get IP on that interface
  LOCAL_IP=""
  if command_exists ipconfig; then
    LOCAL_IP=$(ipconfig getifaddr "$INTERFACE" 2>/dev/null || true)
  fi
  if [ -z "$LOCAL_IP" ]; then
    echo "Could not determine local IP on $INTERFACE." >&2
    exit 1
  fi
  OCT1=$(echo "$LOCAL_IP" | awk -F. '{print $1}')
  OCT2=$(echo "$LOCAL_IP" | awk -F. '{print $2}')
  OCT3=$(echo "$LOCAL_IP" | awk -F. '{print $3}')
  SUBNET="$OCT1.$OCT2.$OCT3.0/24"
fi

# Normalize subnet to a /24 with a prefix like A.B.C.
prefix_from_subnet() {
  local sn="$1"
  local pfx
  case "$sn" in
    *"/24") pfx="$(echo "$sn" | awk -F/ '{print $1}' | awk -F. '{print $1"."$2"."$3"."}')" ;;
    *".")   pfx="$sn" ;;
    *)
      # Try to treat A.B.C.D as A.B.C.
      if echo "$sn" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        pfx="$(echo "$sn" | awk -F. '{print $1"."$2"."$3"."}')"
      else
        echo "Unsupported subnet format: $sn (use A.B.C.0/24 or A.B.C.)" >&2
        return 1
      fi
      ;;
  esac
  printf "%s" "$pfx"
}

# Generate 1..254 safely across macOS/Linux
gen_host_range() {
  if command_exists seq; then
    seq 1 254
  else
    # macOS has jot
    jot 254 1
  fi
}

limit_jobs() {
  # Wait until background jobs fall below CONCURRENCY
  while :; do
    local running
    running=$(jobs -rp | wc -l | tr -d ' ')
    [ "$running" -lt "$CONCURRENCY" ] && break
    sleep 0.05
  done
}

resolve_hostname() {
  local ip="$1" name=""
  # Try ARP table first (fast if present)
  name=$(arp -a 2>/dev/null | awk -v ip="($ip)" '$2==ip {print $1}')
  if [ -n "$name" ] && [ "$name" != "?" ]; then
    printf "%s" "$name"; return 0
  fi
  if command_exists host; then
    name=$(host -W 1 "$ip" 2>/dev/null | awk '/pointer/ {print $5}' | sed 's/\.$//' | head -n1)
  fi
  if [ -z "$name" ] && command_exists dig; then
    name=$(dig +time=1 +tries=1 +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -n1)
  fi
  if [ -z "$name" ] && command_exists nslookup; then
    name=$(nslookup "$ip" 2>/dev/null | awk -F'name = ' '/name = / {gsub(/\.$/,"",$2); print $2; exit}')
  fi
  if [ -z "$name" ]; then
    printf "-"
  else
    printf "%s" "$name"
  fi
}

lookup_mac() {
  local ip="$1" mac=""
  mac=$(arp -n "$ip" 2>/dev/null | awk '/ at / {print $4; exit}')
  if [ -z "$mac" ]; then
    mac=$(arp -a 2>/dev/null | awk -v ip="($ip)" '$2==ip {print $4; exit}')
  fi
  [ -z "$mac" ] && mac="-"
  printf "%s" "$mac"
}

scan_ports_nc() {
  local ip="$1" ports_csv="$2" timeout="$3" open=""
  IFS=',' read -r -a arr <<< "$ports_csv"
  for port in "${arr[@]}"; do
    port=$(echo "$port" | tr -d ' ')
    [ -z "$port" ] && continue
    # macOS nc supports -G (TCP connect timeout)
    if nc -z -G "$timeout" "$ip" "$port" >/dev/null 2>&1; then
      if [ -z "$open" ]; then open="$port"; else open="$open,$port"; fi
    fi
  done
  printf "%s" "${open:-}"
}

scan_with_nmap() {
  local subnet="$1" ports_csv="$2" timeout="$3"
  local tmp_alive tmp_ports
  tmp_alive=$(mktemp)
  tmp_ports=$(mktemp)

  # 1) Host discovery
  nmap -n -sn "$subnet" -oG - 2>/dev/null | awk '/Status: Up/ {print $2}' > "$tmp_alive"

  # 2) Port scan only alive hosts; if none, exit
  if [ ! -s "$tmp_alive" ]; then
    : > "$tmp_ports"
  else
    # nmap takes seconds; --max-retries and --host-timeout help keep it bounded
    # We keep it TCP-only for speed; UDP can be very slow.
    nmap -n -T4 --max-retries 2 --host-timeout "$((timeout*5))s" -p "$ports_csv" --open -oG - $(tr '\n' ' ' < "$tmp_alive") 2>/dev/null \
      | awk -F'[ (]|Ports: ' '/Host: / {ip=$2} /Ports: / {gsub(/\r|\n/,"",$0); split($0,a,"Ports: "); print ip"\t"a[2]}' > "$tmp_ports"
  fi

  # Build an associative-like map in files for port results per IP
  # Will echo: IP<TAB>comma_ports
  awk -F'\t' '{
    ip=$1; ports=$2;
    # Extract only open ports numbers from nmap grepable line
    out="";
    n=split(ports, p, ",");
    for (i=1;i<=n;i++) {
      if (p[i] ~ /open/) {
        sub(/^[ ]*/, "", p[i]);
        split(p[i], f, "/");
        if (out=="") out=f[1]; else out=out","f[1];
      }
    }
    print ip"\t"out
  }' "$tmp_ports"

  rm -f "$tmp_alive" "$tmp_ports"
}

print_header() {
  case "$FORMAT" in
    text)
      printf "%-15s  %-32s  %-17s  %s\n" "IP" "Hostname" "MAC" "Open TCP Ports"
      ;;
    csv)
      printf "IP,Hostname,MAC,OpenTCPPorts\n"
      ;;
    json)
      printf "[\n"
      ;;
  esac
}

print_row() {
  local ip="$1" name="$2" mac="$3" ports="$4"
  case "$FORMAT" in
    text)
      printf "%-15s  %-32s  %-17s  %s\n" "$ip" "$name" "$mac" "${ports:-}"
      ;;
    csv)
      # Escape double-quotes if any
      name=${name//\"/""}
      printf '"%s","%s","%s","%s"\n' "$ip" "$name" "$mac" "${ports:-}"
      ;;
    json)
      # Basic JSON escaping for name
      local n_esc
      n_esc=$(printf '%s' "$name" | python -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null || printf '"%s"' "$name")
      # Remove surrounding quotes if python fallback failed to wrap
      if echo "$n_esc" | grep -q '^[^"]'; then n_esc="\"$name\""; fi
      printf '  {"ip":"%s","hostname":%s,"mac":"%s","open_tcp_ports":"%s"},\n' "$ip" "$n_esc" "$mac" "${ports:-}"
      ;;
  esac
}

print_footer() {
  case "$FORMAT" in
    json)
      # Trim trailing comma: rely on sed if available
      :
      ;;
  esac
}

# Main
main() {
  local prefix
  prefix=$(prefix_from_subnet "$SUBNET") || exit 1

  local tmpdir
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT

  local alive_file ports_map all_results
  alive_file="$tmpdir/alive.txt"
  ports_map="$tmpdir/ports.tsv"   # IP<TAB>ports
  all_results="$tmpdir/results.tsv"  # IP<TAB>name<TAB>mac<TAB>ports

  echo "[+] Scanning subnet: ${prefix}0/24"

  if [ "$USE_NMAP" -eq 1 ] && command_exists nmap; then
    echo "[+] Using nmap for discovery and port scan"
    # Discovery via nmap
    nmap -n -sn "${prefix}0/24" -oG - 2>/dev/null | awk '/Status: Up/ {print $2}' > "$alive_file"
    # Ports via nmap
    scan_with_nmap "${prefix}0/24" "$PORTS" "$TIMEOUT" > "$ports_map"
  else
    echo "[+] Discovering live hosts with ping (parallel: $CONCURRENCY)"
    : > "$alive_file"
    for i in $(gen_host_range); do
      ip="${prefix}${i}"
      limit_jobs
      (
        if ping -c 1 -W "$TIMEOUT" "$ip" >/dev/null 2>&1; then
          echo "$ip" >> "$alive_file"
        fi
      ) &
    done
    wait
    echo "[+] Live hosts found: $(wc -l < "$alive_file" | tr -d ' ')"

    echo "[+] Scanning TCP ports with nc"
    : > "$ports_map"
    while IFS= read -r ip; do
      ports_open=$(scan_ports_nc "$ip" "$PORTS" "$TIMEOUT")
      printf "%s\t%s\n" "$ip" "$ports_open" >> "$ports_map"
    done < "$alive_file"
  fi

  # Build result rows
  : > "$all_results"
  while IFS= read -r ip; do
    name=$(resolve_hostname "$ip")
    mac=$(lookup_mac "$ip")
    ports_open=$(awk -F'\t' -v target="$ip" '$1==target {print $2}' "$ports_map" | head -n1)
    printf "%s\t%s\t%s\t%s\n" "$ip" "$name" "$mac" "$ports_open" >> "$all_results"
  done < <(sort -t . -k1,1n -k2,2n -k3,3n -k4,4n "$alive_file")

  # Output
  print_header
  case "$FORMAT" in
    text)
      awk -F'\t' '{printf("%-15s  %-32s  %-17s  %s\n", $1,$2,$3,$4)}' "$all_results"
      ;;
    csv)
      awk -F'\t' '{gsub(/"/,"""",$2); printf("\"%s\",\"%s\",\"%s\",\"%s\"\n", $1,$2,$3,$4)}' "$all_results"
      ;;
    json)
      { echo "["; awk -F'\t' '{printf("  {\"ip\":\"%s\",\"hostname\":\"%s\",\"mac\":\"%s\",\"open_tcp_ports\":\"%s\"}%s\n", $1,$2,$3,$4, NR==NR?",":"")}' "$all_results"; echo "]"; } | \
      awk 'BEGIN{first=1} /^[ ]*\{/ { if (!first) print prev","; prev=$0; first=0; next } { if ($0 != "[") print } END{ if (prev) print prev; print "]" }'
      ;;
  esac

  echo "[+] Done"
}

main "$@"

