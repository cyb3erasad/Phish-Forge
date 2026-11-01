#!/usr/bin/env bash
# ============================================================
# Phish Forge - Phishing .eml Triage Analyzer
# Author: [Cyb3r Asad]
# Version: 1.4 (Solid Block Logo)
# ============================================================

set -euo pipefail

# --- COLORS & UI ---
PURPLE='\033[38;5;165m' # Neon Purple
CYAN='\033[0;36m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

show_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝███████║██║███████╗███████║    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
██║     ██║  ██║██║███████║██║  ██║    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
EOF
    echo -e "${NC}"
    echo -e "${CYAN}======================================================${NC}"
    echo -e "${CYAN}   Phishing .eml Triage Analyzer${NC}"
    echo -e "${CYAN}   Version 1.4 | Author: [Cyb3r Asad]${NC}"
    echo -e "${CYAN}======================================================${NC}\n"
}

show_help() {
    echo -e "Usage: $0 -f <file.eml> [-o <output_dir>]"
    exit 1
}

# --- ARGUMENT PARSING ---
EML_FILE=""
OUT_DIR=""

while getopts "f:o:h" opt; do
  case ${opt} in
    f ) EML_FILE=$OPTARG ;;
    o ) OUT_DIR=$OPTARG ;;
    h ) show_banner; show_help ;;
    \? ) echo -e "${RED}Invalid option. Use -h for help.${NC}"; exit 1 ;;
  esac
done

if [ -z "$EML_FILE" ] || [ ! -f "$EML_FILE" ]; then
    show_banner
    echo -e "${RED}[!] Error: Valid input file required.${NC}"
    show_help
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -z "$OUT_DIR" ]; then OUT_DIR="./reports/phish-forge-${TS}"; fi
mkdir -p "$OUT_DIR"/{headers,urls,attachments}
REPORT="$OUT_DIR/report.txt"
: > "$REPORT"

# --- SCORING ENGINE ---
SCORE=0
declare -a FINDINGS=()
log()     { printf "%b\n" "$*" | tee -a "$REPORT"; }
finding() { FINDINGS+=("$1"); SCORE=$((SCORE + ${2:-0})); }

# --- MODULES ---

extract_headers() {
  python3 - "$EML_FILE" > "$OUT_DIR/headers/all.txt" <<'PY'
import sys, email
with open(sys.argv[1], 'rb') as f:
    msg = email.message_from_binary_file(f)
for k, v in msg.items():
    print(f"{k}: {' '.join(v.split())}")
PY
}

check_mismatch() {
  local from reply rp from_dom="" reply_dom="" rp_dom=""
  from=$(awk -F': ' 'tolower($1)=="from"{sub(/^[^:]*: /,"");print;exit}' "$OUT_DIR/headers/all.txt" || true)
  reply=$(awk -F': ' 'tolower($1)=="reply-to"{sub(/^[^:]*: /,"");print;exit}' "$OUT_DIR/headers/all.txt" || true)
  rp=$(awk -F': ' 'tolower($1)=="return-path"{sub(/^[^:]*: /,"");print;exit}' "$OUT_DIR/headers/all.txt" || true)

  [[ -n "$from"  ]] && from_dom=$(grep -oE '@[A-Za-z0-9.-]+' <<<"$from" | head -1 | tr -d '@' || true)
  [[ -n "$reply" ]] && reply_dom=$(grep -oE '@[A-Za-z0-9.-]+' <<<"$reply" | head -1 | tr -d '@' || true)
  [[ -n "$rp"    ]] && rp_dom=$(grep -oE '@[A-Za-z0-9.-]+'    <<<"$rp"    | head -1 | tr -d '@' || true)

  log "${CYAN}From:${NC}        $from"
  log "${CYAN}Reply-To:${NC}    ${reply:-<none>}"
  log "${CYAN}Return-Path:${NC} ${rp:-<none>}"

  if [[ -n "$reply_dom" && "$reply_dom" != "$from_dom" ]]; then
    finding "From/Reply-To domain mismatch ($from_dom vs $reply_dom)" 2
  fi
  if [[ -n "$rp_dom" && "$rp_dom" != "$from_dom" ]]; then
    finding "From/Return-Path domain mismatch ($from_dom vs $rp_dom)" 2
  fi
}

check_auth() {
  local ar
  ar=$(grep -i '^Authentication-Results:' "$OUT_DIR/headers/all.txt" | tail -1 || true)
  if [[ -z "$ar" ]]; then
    finding "No Authentication-Results header found" 1
    return
  fi
  
  local ar_clean
  ar_clean=$(echo "$ar" | sed -E 's/^Authentication-Results:\s*//i')
  log "\n${CYAN}Auth-Results:${NC} $ar_clean"

  if grep -qi 'spf=fail' <<<"$ar"; then finding "SPF Fail" 3; fi
  if grep -qi 'dkim=fail' <<<"$ar"; then finding "DKIM Fail" 2; fi
  if grep -qi 'dmarc=fail' <<<"$ar"; then finding "DMARC Fail" 3; fi
}

extract_urls() {
  python3 - "$EML_FILE" > "$OUT_DIR/urls/raw.txt" <<'PY'
import sys, email, re
with open(sys.argv[1], 'rb') as f:
    msg = email.message_from_binary_file(f)
urls = set()
for part in msg.walk():
    if part.get_content_type() not in ('text/plain', 'text/html'): continue
    try:
        payload = part.get_payload(decode=True)
        if payload is None: continue
        text = payload.decode(part.get_content_charset() or 'utf-8', 'replace')
    except Exception: continue
    for m in re.findall(r'https?://[^\s"\'<>()]+', text, re.I):
        urls.add(m.rstrip('.,;)]'))
for u in sorted(urls): print(u)
PY
  sort -u "$OUT_DIR/urls/raw.txt" > "$OUT_DIR/urls/unique.txt"
  awk -F/ '{print $3}' "$OUT_DIR/urls/unique.txt" | grep -v '^$' | sort -u > "$OUT_DIR/urls/domains.txt" || true
  
  local n=$(wc -l < "$OUT_DIR/urls/unique.txt" | tr -d ' ')
  log "\n${CYAN}URLs Found:${NC} $n"
  if [[ "$n" -gt 5 ]]; then finding "Unusually high URL count ($n)" 1; fi
}

extract_attachments() {
  if command -v ripmime >/dev/null 2>&1; then
    ripmime -i "$EML_FILE" -d "$OUT_DIR/attachments" --no-nameless >/dev/null 2>&1 || true
    if compgen -G "$OUT_DIR/attachments/*" >/dev/null; then
      ( cd "$OUT_DIR/attachments" && sha256sum * > hashes.txt )
      local count=$(wc -l < "$OUT_DIR/attachments/hashes.txt" | tr -d ' ')
      log "\n${CYAN}Attachments:${NC} $count found"
      finding "Message contains attachments" 1
    fi
  else
    log "\n${YELLOW}[!] ripmime not installed; skipping attachments${NC}"
  fi
}

enrich_vt() {
  if [[ -z "${VT_API_KEY:-}" ]]; then return; fi
  
  log "\n${CYAN}[*] VirusTotal Enrichment:${NC}"
  local dom resp mal
  while IFS= read -r dom; do
    [[ -z "$dom" ]] && continue
    resp=$(curl -s --max-time 10 -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/$dom" 2>/dev/null || true)
    mal=$(jq -r '.data.attributes.last_analysis_stats.malicious // 0' <<<"$resp" 2>/dev/null || echo 0)
    if [[ "$mal" -gt 0 ]]; then
        log "  ${RED}[!] $dom -> $mal malicious engines${NC}"
        finding "VT flagged $dom ($mal engines)" 4
    else
        log "  ${GREEN}[+] $dom -> Clean${NC}"
    fi
    sleep 15
  done < "$OUT_DIR/urls/domains.txt"
}

verdict() {
  local v color
  if   (( SCORE >= 6 )); then v="MALICIOUS"; color=$RED
  elif (( SCORE >= 3 )); then v="SUSPICIOUS"; color=$YELLOW
  else                        v="LIKELY CLEAN"; color=$GREEN
  fi
  
  log "\n${PURPLE}======================================================${NC}"
  log "${color} VERDICT: $v  (Score: $SCORE)${NC}"
  log "${PURPLE}======================================================${NC}"
  log "Findings:"
  for f in "${FINDINGS[@]}"; do log "  [!] $f"; done
  log "\nArtifacts saved to: $OUT_DIR"
}

# --- MAIN EXECUTION ---
show_banner
echo -e "${CYAN}[*] Analyzing:${NC} $EML_FILE"
echo -e "${CYAN}[*] Output Dir:${NC} $OUT_DIR\n"
echo -e "${PURPLE}------------------------------------------------------${NC}"

extract_headers
check_mismatch
check_auth
extract_urls
extract_attachments
enrich_vt
verdict
