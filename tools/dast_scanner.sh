#!/usr/bin/env bash
# =============================================================================
# dast_scanner.sh — DAST Scanner Wrapper for Unified Bug Hunter
#
# Runs OWASP ZAP or nuclei for automated vulnerability scanning.
# Results are imported into the bug hunter database.
#
# Usage:
#   ./tools/dast_scanner.sh zap https://example.com [--api-key KEY]
#   ./tools/dast_scanner.sh nuclei https://example.com [-t cves,technologies]
#   ./tools/dast_scanner.sh list                  # List available scan templates
#   ./tools/dast_scanner.sh import results.json    # Import external scan results
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DB_PATH="${PROJECT_DIR}/dashboard/data/bughunter.db"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[-]${NC} $1"; }

usage() {
    cat <<EOF
DAST Scanner — Automated Vulnerability Scanning

Commands:
  zap <url>              Run OWASP ZAP full scan
  nuclei <url>           Run nuclei scan (fast)
  nuclei-deep <url>      Run nuclei with all templates
  list                   List available scan types/templates
  import <file>          Import results from JSON file

Options:
  --api-key KEY          ZAP API key (default: changeme)
  -t, --templates LIST   Comma-separated nuclei template filters
  -o, --output FILE      Save results to file
  -q, --quiet            Minimal output
EOF
}

ensure_db() {
    mkdir -p "$(dirname "$DB_PATH")"
    if [ ! -f "$DB_PATH" ]; then
        log "Initializing database..."
        python3 -c "from dashboard.database import init_db; init_db()"
    fi
}

import_finding() {
    local target_id="$1" title="$2" severity="$3" class="$4" endpoint="$5" desc="$6"
    python3 -c "
from dashboard.database import add_finding
add_finding($target_id, '$title', '$severity', '$class', endpoint='$endpoint', description='''$desc''', source='dast')
" 2>/dev/null || warn "Failed to import finding: $title"
}

run_zap() {
    local url="$1"
    local api_key="${ZAP_API_KEY:-changeme}"
    log "Running OWASP ZAP scan against ${url}"
    warn "Make sure ZAP is running:  java -jar zap.jar -daemon -port 8080"

    # Check if ZAP is running
    if ! curl -s "http://localhost:8080" >/dev/null 2>&1; then
        err "ZAP is not running. Start it with: zap.sh -daemon -port 8080"
        return 1
    fi

    # Spider
    log "Spidering ${url}..."
    curl -s "http://localhost:8080/JSON/spider/action/scan/?apikey=${api_key}&url=${url}&maxChildren=5" >/dev/null
    sleep 5

    # Active scan
    log "Running active scan (this may take a while)..."
    local scan_id
    scan_id=$(curl -s "http://localhost:8080/JSON/ascanner/action/scan/?apikey=${api_key}&url=${url}&recurse=true" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan',''))" 2>/dev/null || echo "")

    if [ -n "$scan_id" ]; then
        while true; do
            local progress
            progress=$(curl -s "http://localhost:8080/JSON/ascanner/view/status/?apikey=${api_key}&scanId=${scan_id}" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','0'))" 2>/dev/null || echo "0")
            echo -ne "\r  Progress: ${progress}%    "
            [ "$progress" = "100" ] && break
            sleep 10
        done
        echo ""
    fi

    # Get alerts
    log "Fetching alerts..."
    local alerts
    alerts=$(curl -s "http://localhost:8080/JSON/core/view/alerts/?apikey=${api_key}&baseurl=${url}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data.get('alerts', []):
    print(json.dumps({
        'name': a.get('name'),
        'risk': a.get('risk'),
        'confidence': a.get('confidence'),
        'url': a.get('url'),
        'description': a.get('description'),
        'solution': a.get('solution'),
    }))
" 2>/dev/null)

    local count=0
    local output_file="${3:-}"
    [ -n "$output_file" ] && echo "$alerts" > "$output_file"

    ensure_db
    local target_id
    target_id=$(python3 -c "
from dashboard.database import add_target, get_targets
add_target('$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)')
for t in get_targets():
    if t['domain'] == '$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)':
        print(t['id'])
        break
" 2>/dev/null || echo "1")

    while IFS= read -r alert; do
        [ -z "$alert" ] && continue
        local name risk endpoint
        name=$(echo "$alert" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('name','Unknown'))" 2>/dev/null)
        risk=$(echo "$alert" | python3 -c "import sys,json; r=json.loads(sys.stdin.read()).get('risk',''); print({'0':'info','1':'low','2':'medium','3':'high'}.get(r,'info'))" 2>/dev/null)
        endpoint=$(echo "$alert" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('url',''))" 2>/dev/null)
        desc=$(echo "$alert" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('description',''))" 2>/dev/null)

        import_finding "$target_id" "$name" "$risk" "dast" "$endpoint" "$desc"
        count=$((count + 1))
    done <<< "$alerts"

    log "Imported ${count} findings from ZAP scan"
}

run_nuclei() {
    local url="$1"
    local template_filter="${2:-cves,exposures,misconfiguration}"
    local output_file="${3:-}"

    log "Running nuclei against ${url} (templates: ${template_filter})"

    local cmd="nuclei -u ${url} -t ${template_filter} -json -silent"
    [ -n "$output_file" ] && cmd="${cmd} -o ${output_file}"

    local results
    results=$(eval "$cmd" 2>/dev/null || true)

    local count=0
    ensure_db
    local target_id
    target_id=$(python3 -c "
from dashboard.database import add_target, get_targets
add_target('$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)')
for t in get_targets():
    if t['domain'] == '$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)':
        print(t['id'])
        break
" 2>/dev/null || echo "1")

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local name severity template endpoint desc
        name=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin).get('info',{}).get('name','Unknown'))" 2>/dev/null)
        severity=$(echo "$line" | python3 -c "import sys,json; print(json.loads(sys.stdin).get('info',{}).get('severity','info'))" 2>/dev/null)
        template=$(echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin).get('matched-at',''); print(d)" 2>/dev/null)

        import_finding "$target_id" "$name" "$severity" "nuclei" "$template" "$line"
        count=$((count + 1))
    done <<< "$results"

    log "Imported ${count} findings from nuclei scan"
}

run_nuclei_deep() {
    local url="$1"
    log "Running deep nuclei scan with ALL templates..."
    run_nuclei "$url" "all-templates"
}

import_results() {
    local file="$1"
    if [ ! -f "$file" ]; then
        err "File not found: $file"
        return 1
    fi
    log "Importing results from ${file}"

    ensure_db
    python3 -c "
import json
from dashboard.database import add_finding, add_target, get_targets

with open('$file') as f:
    data = json.load(f)

findings = data if isinstance(data, list) else [data]
for f in findings:
    domain = f.get('url', f.get('host', 'unknown'))
    domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    add_target(domain)
    targets = get_targets()
    target_id = targets[0]['id'] if targets else 1
    add_finding(
        target_id or 1,
        f.get('name', f.get('title', 'Imported finding')),
        f.get('severity', f.get('risk', 'info')),
        f.get('class', f.get('bug_class', 'imported')),
        endpoint=f.get('url', f.get('endpoint', '')),
        description=f.get('description', f.get('info', str(f))),
        source='dast-import'
    )
    " 2>/dev/null && log "Import complete" || err "Import failed"
}

# --- Main ---
case "${1:-help}" in
    zap)
        [ -z "${2:-}" ] && { err "Usage: $0 zap <url>"; exit 1; }
        run_zap "$2" "${3:-}" "${4:-}"
        ;;
    nuclei)
        [ -z "${2:-}" ] && { err "Usage: $0 nuclei <url> [templates] [output]"; exit 1; }
        run_nuclei "$2" "${3:-cves,exposures,misconfiguration}" "${4:-}"
        ;;
    nuclei-deep)
        [ -z "${2:-}" ] && { err "Usage: $0 nuclei-deep <url>"; exit 1; }
        run_nuclei_deep "$2"
        ;;
    list)
        echo "Available scan types:"
        echo "  zap          - OWASP ZAP full DAST scan (requires ZAP running)"
        echo "  nuclei       - Fast nuclei scan (cves, exposures, misconfig)"
        echo "  nuclei-deep  - All nuclei templates (slow)"
        echo "  import FILE  - Import external scan results (JSON)"
        echo ""
        echo "Nuclei template categories: cves, exposures, misconfiguration,"
        echo "  vulnerabilities, technologies, takeovers, panels, dast"
        ;;
    import)
        [ -z "${2:-}" ] && { err "Usage: $0 import <file>"; exit 1; }
        import_results "$2"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        err "Unknown command: $1"
        usage
        exit 1
        ;;
esac
