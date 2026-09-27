#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run with sudo bash setup.sh' >&2; exit 1; }
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
command -v curl >/dev/null || { apt-get update; apt-get install -y curl ca-certificates; }
FILE=$(mktemp)
trap 'rm -f -- "$FILE"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 20 --max-time 300 -o "$FILE" https://raw.githubusercontent.com/alirezachatgpt97-coder/alireza-dns/main/install.sh
printf '%s  %s\n' '6de165c93ec76176af73318d0dabdf8110f1350a19f5962aadabdc43b7e1a761' "$FILE" | sha256sum --check --status || { echo 'Installer checksum mismatch; nothing executed.' >&2; exit 1; }
bash -n "$FILE"
bash "$FILE" "$@"
