#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="ipload-balancer"
CONFIG_FILE="${CONFIG_FILE:-/etc/ipload-balancer.conf}"
STATE_DIR="${STATE_DIR:-/var/lib/ipload-balancer}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/ipload-balancer}"
LOG_TAG="${LOG_TAG:-ipload-balancer}"

PUBLIC_IFACE=""
LAN_CIDR=""
PUBLIC_IPS=()
MODE="balance"
BALANCE_METHOD="random"
ROTATE_SECONDS="300"
CHECK_INTERVAL="5"
REACTION_COOLDOWN="60"
ATTACK_RX_PPS="80000"
ATTACK_RX_BPS="100000000"
ATTACK_SYN_RECV="1500"
ATTACK_CONNTRACK_USAGE="85"
ENABLE_INPUT_GUARD="yes"
PROTECTED_PORTS="22,80,443"
DROP_ATTACKED_IP_SECONDS="90"
ENABLE_SYSCTL_HARDENING="yes"
ENABLE_BOGON_DROP="yes"
ENABLE_PACKET_LOG="no"
PACKET_LOG_RATE="30/minute"
GEO_POLICY="off"
GEO_COUNTRIES=()
GEO_SOURCE_URL="https://www.ipdeny.com/ipblocks/data/countries"
GEO_REFRESH_HOURS="24"

NFT_TABLE_NAT="ip ipload_nat"
NFT_TABLE_GUARD="inet ipload_guard"

log() {
  local level="$1"
  shift
  printf '%s [%s] %s\n' "$(date -Is)" "$level" "$*"
  if command -v logger >/dev/null 2>&1; then
    logger -t "$LOG_TAG" "[$level] $*"
  fi
}

die() {
  log ERROR "$*"
  exit 1
}

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root."
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

load_config() {
  [[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
  [[ -n "$PUBLIC_IFACE" ]] || die "PUBLIC_IFACE is required."
  [[ "${#PUBLIC_IPS[@]}" -gt 0 ]] || die "PUBLIC_IPS must contain at least one IP."
}

ensure_dirs() {
  mkdir -p "$STATE_DIR" "$RUNTIME_DIR"
  chmod 700 "$STATE_DIR" "$RUNTIME_DIR"
}

join_csv_as_nft_set() {
  local csv="$1"
  local out=""
  IFS=',' read -ra items <<< "$csv"
  for item in "${items[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -z "$item" ]] && continue
    out+="${out:+, }$item"
  done
  printf '%s' "$out"
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

geo_dir() {
  printf '%s/geo' "$STATE_DIR"
}

geo_set_name() {
  case "$GEO_POLICY" in
    allow) printf 'country_allow4' ;;
    block) printf 'country_block4' ;;
    off) printf '' ;;
    *) die "Unsupported GEO_POLICY: $GEO_POLICY" ;;
  esac
}

bogon_elements() {
  cat <<'EOF'
0.0.0.0/8,
10.0.0.0/8,
100.64.0.0/10,
127.0.0.0/8,
169.254.0.0/16,
172.16.0.0/12,
192.0.0.0/24,
192.0.2.0/24,
192.168.0.0/16,
198.18.0.0/15,
198.51.100.0/24,
203.0.113.0/24,
224.0.0.0/4,
240.0.0.0/4
EOF
}

enable_sysctl_hardening() {
  [[ "$ENABLE_SYSCTL_HARDENING" == "yes" ]] || return 0
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
  sysctl -w "net.ipv4.conf.${PUBLIC_IFACE}.rp_filter=0" >/dev/null || true
}

ensure_public_ips_on_iface() {
  local ip
  for ip in "${PUBLIC_IPS[@]}"; do
    if ! ip -4 addr show dev "$PUBLIC_IFACE" | grep -qw "$ip"; then
      log INFO "Adding $ip/32 to $PUBLIC_IFACE"
      ip addr add "$ip/32" dev "$PUBLIC_IFACE"
    fi
  done
}

build_snat_map() {
  local i=0
  local map=""
  for ipaddr in "${PUBLIC_IPS[@]}"; do
    map+="${map:+, }$i : $ipaddr"
    i=$((i + 1))
  done
  printf '%s' "$map"
}

apply_balance_rules() {
  local map modulo method_expr from_filter
  map="$(build_snat_map)"
  modulo="${#PUBLIC_IPS[@]}"
  from_filter=""
  [[ -n "$LAN_CIDR" ]] && from_filter="ip saddr $LAN_CIDR "

  case "$BALANCE_METHOD" in
    random) method_expr="numgen random mod $modulo" ;;
    persistent) method_expr="jhash ip saddr . ip daddr mod $modulo" ;;
    *) die "Unsupported BALANCE_METHOD: $BALANCE_METHOD" ;;
  esac

  nft delete table $NFT_TABLE_NAT >/dev/null 2>&1 || true
  nft -f - <<EOF
table $NFT_TABLE_NAT {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "$PUBLIC_IFACE" ${from_filter}snat to $method_expr map { $map }
  }
}
EOF
}

apply_rotate_rules() {
  local index="$1"
  local ipaddr="${PUBLIC_IPS[$index]}"
  local from_filter=""
  [[ -n "$LAN_CIDR" ]] && from_filter="ip saddr $LAN_CIDR "

  nft delete table $NFT_TABLE_NAT >/dev/null 2>&1 || true
  nft -f - <<EOF
table $NFT_TABLE_NAT {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "$PUBLIC_IFACE" ${from_filter}snat to $ipaddr
  }
}
EOF
  printf '%s\n' "$index" > "$STATE_DIR/current-index"
  log INFO "Active egress IP is now $ipaddr"
}

apply_guard_rules() {
  [[ "$ENABLE_INPUT_GUARD" == "yes" ]] || return 0
  local ports bogons log_rule geo_rule
  ports="$(join_csv_as_nft_set "$PROTECTED_PORTS")"
  [[ -n "$ports" ]] || ports="22, 80, 443"
  bogons="$(bogon_elements)"
  log_rule=""
  geo_rule=""

  if [[ "$ENABLE_PACKET_LOG" == "yes" ]]; then
    log_rule="tcp dport { $ports } limit rate $PACKET_LOG_RATE log prefix \"ipload-sample \" flags all"
  fi

  case "$GEO_POLICY" in
    off) geo_rule="" ;;
    allow) geo_rule="tcp dport { $ports } ip saddr != @country_allow4 drop" ;;
    block) geo_rule="tcp dport { $ports } ip saddr @country_block4 drop" ;;
    *) die "Unsupported GEO_POLICY: $GEO_POLICY" ;;
  esac

  nft delete table $NFT_TABLE_GUARD >/dev/null 2>&1 || true
  nft -f - <<EOF
table $NFT_TABLE_GUARD {
  set blacklist4 {
    type ipv4_addr
    flags timeout
  }

  set bogons4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = { $bogons }
  }

  set country_allow4 {
    type ipv4_addr
    flags interval
    auto-merge
  }

  set country_block4 {
    type ipv4_addr
    flags interval
    auto-merge
  }

  chain input {
    type filter hook input priority -100; policy accept;
    ct state invalid drop
    ip saddr @blacklist4 drop
    $(if [[ "$ENABLE_BOGON_DROP" == "yes" ]]; then printf 'ip saddr @bogons4 drop'; fi)
    ct state established,related accept
    iifname "lo" accept
    $geo_rule
    $log_rule
    tcp dport { $ports } ct state new limit rate over 250/second burst 500 packets add @blacklist4 { ip saddr timeout 10m } drop
    tcp flags & (fin|syn|rst|ack) == syn tcp dport { $ports } limit rate over 500/second burst 1000 packets drop
  }
}
EOF
  load_geo_sets
}

cleanup_rules() {
  nft delete table $NFT_TABLE_NAT >/dev/null 2>&1 || true
  nft delete table $NFT_TABLE_GUARD >/dev/null 2>&1 || true
}

current_index() {
  if [[ -f "$STATE_DIR/current-index" ]]; then
    cat "$STATE_DIR/current-index"
  else
    printf '0'
  fi
}

rotate_next() {
  local current next
  current="$(current_index)"
  next=$(( (current + 1) % ${#PUBLIC_IPS[@]} ))
  apply_rotate_rules "$next"
}

read_rx_packets() {
  awk -v iface="$PUBLIC_IFACE" -F'[: ]+' '$2 == iface { print $4 }' /proc/net/dev
}

read_iface_stats() {
  awk -v iface="$PUBLIC_IFACE" -F'[: ]+' '$2 == iface { print $3, $4, $11, $12 }' /proc/net/dev
}

syn_recv_count() {
  if command -v ss >/dev/null 2>&1; then
    ss -Hant state syn-recv 2>/dev/null | wc -l
  else
    printf '0'
  fi
}

conntrack_usage_percent() {
  [[ -r /proc/sys/net/netfilter/nf_conntrack_count ]] || { printf '0'; return; }
  [[ -r /proc/sys/net/netfilter/nf_conntrack_max ]] || { printf '0'; return; }
  local count max
  count="$(cat /proc/sys/net/netfilter/nf_conntrack_count)"
  max="$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
  [[ "$max" -gt 0 ]] || { printf '0'; return; }
  printf '%s' $(( count * 100 / max ))
}

drop_ip_temporarily() {
  local ipaddr="$1"
  [[ "$ENABLE_INPUT_GUARD" == "yes" ]] || return 0
  [[ -n "$ipaddr" ]] || return 0
  [[ "$DROP_ATTACKED_IP_SECONDS" -gt 0 ]] || return 0
  nft add rule inet ipload_guard input ip daddr "$ipaddr" drop comment "\"temporary-ip-rotation-drop\"" >/dev/null 2>&1 || true
  (
    sleep "$DROP_ATTACKED_IP_SECONDS"
    nft -a list chain inet ipload_guard input 2>/dev/null \
      | awk '/temporary-ip-rotation-drop/ { print $NF }' \
      | while read -r handle; do nft delete rule inet ipload_guard input handle "$handle" >/dev/null 2>&1 || true; done
  ) &
}

attack_detected() {
  local prev_rx_packets="$1" current_rx_packets="$2" prev_rx_bytes="$3" current_rx_bytes="$4" seconds="$5"
  local rx_pps rx_bps syns conntrack reasons
  rx_pps=$(( (current_rx_packets - prev_rx_packets) / seconds ))
  [[ "$rx_pps" -lt 0 ]] && rx_pps=0
  rx_bps=$(( (current_rx_bytes - prev_rx_bytes) / seconds ))
  [[ "$rx_bps" -lt 0 ]] && rx_bps=0
  syns="$(syn_recv_count)"
  conntrack="$(conntrack_usage_percent)"
  reasons=""

  printf 'rx_pps=%s rx_bps=%s syn_recv=%s conntrack_usage=%s%%\n' "$rx_pps" "$rx_bps" "$syns" "$conntrack" > "$RUNTIME_DIR/last-metrics"

  [[ "$rx_pps" -ge "$ATTACK_RX_PPS" ]] && reasons="${reasons} rx_pps"
  [[ "$rx_bps" -ge "$ATTACK_RX_BPS" ]] && reasons="${reasons} rx_bps"
  [[ "$syns" -ge "$ATTACK_SYN_RECV" ]] && reasons="${reasons} syn_recv"
  [[ "$conntrack" -ge "$ATTACK_CONNTRACK_USAGE" ]] && reasons="${reasons} conntrack"
  printf 'reasons=%s\n' "${reasons:-none}" >> "$RUNTIME_DIR/last-metrics"
  [[ -n "$reasons" ]] && return 0
  return 1
}

download_geo_country() {
  local code="$1" out="$2" url
  url="${GEO_SOURCE_URL}/$(lower "$code").zone"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$out"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    die "Geo updates require curl or wget."
  fi
}

update_geo() {
  need_root
  load_config
  ensure_dirs
  mkdir -p "$(geo_dir)"
  [[ "$GEO_POLICY" != "off" ]] || die "Set GEO_POLICY to allow or block before updating geo lists."
  [[ "${#GEO_COUNTRIES[@]}" -gt 0 ]] || die "GEO_COUNTRIES is empty."

  local code tmp target
  for code in "${GEO_COUNTRIES[@]}"; do
    code="$(lower "$code")"
    tmp="$(mktemp)"
    target="$(geo_dir)/${code}.zone"
    log INFO "Downloading GeoIP country list: $code"
    download_geo_country "$code" "$tmp"
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$tmp" > "$target"
    rm -f "$tmp"
  done
  date +%s > "$(geo_dir)/updated-at"
  log INFO "GeoIP country lists updated."
}

geo_needs_refresh() {
  [[ "$GEO_POLICY" != "off" ]] || return 1
  [[ "$GEO_REFRESH_HOURS" -gt 0 ]] || return 1
  [[ -f "$(geo_dir)/updated-at" ]] || return 0
  local updated now max_age
  updated="$(cat "$(geo_dir)/updated-at" 2>/dev/null || printf '0')"
  now="$(date +%s)"
  max_age=$((GEO_REFRESH_HOURS * 3600))
  (( now - updated > max_age ))
}

maybe_refresh_geo() {
  if geo_needs_refresh; then
    update_geo || log WARN "Could not refresh GeoIP country lists."
  fi
}

load_geo_sets() {
  [[ "$GEO_POLICY" != "off" ]] || return 0
  [[ "${#GEO_COUNTRIES[@]}" -gt 0 ]] || return 0
  local set_name code file batch line count
  set_name="$(geo_set_name)"
  nft flush set inet ipload_guard "$set_name" >/dev/null 2>&1 || true
  for code in "${GEO_COUNTRIES[@]}"; do
    file="$(geo_dir)/$(lower "$code").zone"
    [[ -f "$file" ]] || continue
    batch=""
    count=0
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      batch+="${batch:+, }$line"
      count=$((count + 1))
      if (( count >= 250 )); then
        nft add element inet ipload_guard "$set_name" "{ $batch }" >/dev/null
        batch=""
        count=0
      fi
    done < "$file"
    [[ -n "$batch" ]] && nft add element inet ipload_guard "$set_name" "{ $batch }" >/dev/null
  done
}

run_daemon() {
  need_root
  need_cmd nft
  need_cmd ip
  load_config
  ensure_dirs
  enable_sysctl_hardening
  ensure_public_ips_on_iface
  maybe_refresh_geo
  apply_guard_rules

  case "$MODE" in
    balance) apply_balance_rules ;;
    rotate) apply_rotate_rules "$(current_index)" ;;
    *) die "Unsupported MODE: $MODE" ;;
  esac

  log INFO "Started with MODE=$MODE PUBLIC_IFACE=$PUBLIC_IFACE IPs=${PUBLIC_IPS[*]}"
  local last_stats now_stats last_rx_bytes last_rx_packets now_rx_bytes now_rx_packets last_reaction last_rotation now
  last_stats="$(read_iface_stats)"
  read -r last_rx_bytes last_rx_packets _ _ <<< "${last_stats:-0 0 0 0}"
  last_reaction=0
  last_rotation="$(date +%s)"

  while true; do
    sleep "$CHECK_INTERVAL"
    now="$(date +%s)"
    now_stats="$(read_iface_stats)"
    read -r now_rx_bytes now_rx_packets _ _ <<< "${now_stats:-$last_rx_bytes $last_rx_packets 0 0}"

    if attack_detected "$last_rx_packets" "$now_rx_packets" "$last_rx_bytes" "$now_rx_bytes" "$CHECK_INTERVAL"; then
      if (( now - last_reaction >= REACTION_COOLDOWN )); then
        log WARN "Attack threshold reached: $(cat "$RUNTIME_DIR/last-metrics")"
        attacked_ip=""
        if [[ "$MODE" == "balance" ]]; then
          MODE="rotate"
          rotate_next
        else
          attacked_ip="${PUBLIC_IPS[$(current_index)]}"
          rotate_next
        fi
        drop_ip_temporarily "$attacked_ip"
        last_reaction="$now"
        last_rotation="$now"
      fi
    elif [[ "$MODE" == "rotate" && "$ROTATE_SECONDS" -gt 0 && $((now - last_rotation)) -ge "$ROTATE_SECONDS" ]]; then
      rotate_next
      last_rotation="$now"
    fi

    last_rx_bytes="$now_rx_bytes"
    last_rx_packets="$now_rx_packets"
  done
}

install_service() {
  need_root
  local target="/usr/local/sbin/ipload-balancer"
  install -m 0755 "$0" "$target"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    die "Install $CONFIG_FILE first. Use ipload-balancer.conf.example as a template."
  fi
  cat > /etc/systemd/system/ipload-balancer.service <<EOF
[Unit]
Description=IP load balancing and defensive rotation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=CONFIG_FILE=$CONFIG_FILE
ExecStart=$target daemon
ExecStopPost=$target cleanup
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable ipload-balancer.service
  log INFO "Installed systemd service. Start with: systemctl start ipload-balancer"
}

status() {
  load_config
  printf 'Config: %s\n' "$CONFIG_FILE"
  printf 'Mode: %s\n' "$MODE"
  printf 'Interface: %s\n' "$PUBLIC_IFACE"
  printf 'IPs: %s\n' "${PUBLIC_IPS[*]}"
  [[ -f "$RUNTIME_DIR/last-metrics" ]] && cat "$RUNTIME_DIR/last-metrics"
  if [[ "$GEO_POLICY" != "off" ]]; then
    printf 'Geo policy: %s %s\n' "$GEO_POLICY" "${GEO_COUNTRIES[*]:-}"
    [[ -f "$(geo_dir)/updated-at" ]] && date -d "@$(cat "$(geo_dir)/updated-at")" '+Geo updated: %F %T %Z' 2>/dev/null || true
  fi
  nft list table $NFT_TABLE_NAT 2>/dev/null || true
  nft list table $NFT_TABLE_GUARD 2>/dev/null || true
}

usage() {
  cat <<EOF
Usage: $0 <command>

Commands:
  daemon      Run the monitor and apply nftables rules
  apply       Apply configured rules once and exit
  rotate      Rotate to the next IP once
  update-geo  Download country CIDR lists used by GEO_POLICY
  cleanup     Remove nftables tables created by this tool
  install     Install /usr/local/sbin/ipload-balancer and systemd unit
  status      Show config, metrics, and nftables rules

Set CONFIG_FILE=/path/to/config to use a non-default config.
EOF
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    daemon) run_daemon ;;
    apply)
      need_root; need_cmd nft; need_cmd ip; load_config; ensure_dirs
      enable_sysctl_hardening; ensure_public_ips_on_iface; maybe_refresh_geo; apply_guard_rules
      [[ "$MODE" == "balance" ]] && apply_balance_rules || apply_rotate_rules "$(current_index)"
      ;;
    rotate) need_root; need_cmd nft; load_config; ensure_dirs; apply_guard_rules; rotate_next ;;
    update-geo) update_geo ;;
    cleanup) need_root; cleanup_rules ;;
    install) install_service ;;
    status) status ;;
    -h|--help|help|"") usage ;;
    *) usage; exit 2 ;;
  esac
}

main "$@"
