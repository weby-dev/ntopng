#!/bin/bash
# =============================================================================
#  setup.sh — ntopng-analyzer Auto Installer
#  Repo: https://github.com/weby-dev/ntopng
#
#  Usage:
#    curl -fsSL https://raw.githubusercontent.com/weby-dev/ntopng/main/setup.sh | sudo bash
#  Or:
#    sudo bash setup.sh [OPTIONS]
#
#  Options:
#    --db-host       MySQL host         (default: 127.0.0.1)
#    --db-port       MySQL port         (default: 3306)
#    --db-name       Database name      (default: ntopng_threats)
#    --db-user       DB username        (default: ntopng_user)
#    --db-pass       DB password        (auto-generated if omitted)
#    --smtp-host     SMTP host          (default: localhost)
#    --smtp-port     SMTP port          (default: 25)
#    --smtp-from     From address       (required)
#    --victim-cc     CC emails          (comma-separated, required)
#    --api-port      API listen port    (default: 8765)
#    --api-token     API bearer token   (auto-generated if omitted)
#    --log-base      Log base dir       (default: /var/log/remote)
#    --install-dir   Install path       (default: /opt/ntopng-analyzer)
#    --no-service    Skip systemd setup
#    --no-cron       Skip crontab setup
#    --uninstall     Remove everything
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m';     NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }
step()    { echo -e "\n${BOLD}━━━  $*  ━━━${NC}"; }

# ── Defaults ──────────────────────────────────────────────────────────────────
GITHUB_REPO="https://github.com/weby-dev/ntopng.git"
INSTALL_DIR="/opt/ntopng-analyzer"
SVC_USER="ntopng-analyzer"
LOG_DIR="/var/log/ntopng_analyzer"

DB_HOST="127.0.0.1"
DB_PORT="3306"
DB_NAME="ntopng_threats"
DB_USER="ntopng_user"
DB_PASS=""          # generated below if empty

SMTP_HOST="localhost"
SMTP_PORT="25"
SMTP_TLS="false"
SMTP_FROM=""
SMTP_FROM_NAME="NOC Security Team"
SMTP_USER=""
SMTP_PASS=""

VICTIM_CC=""
API_HOST="0.0.0.0"
API_PORT="8765"
API_TOKEN=""        # generated below if empty
LOG_BASE="/var/log/remote"

DO_SERVICE=true
DO_CRON=true
DO_UNINSTALL=false

# ── Argument Parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --db-host)      DB_HOST="$2";       shift 2 ;;
        --db-port)      DB_PORT="$2";       shift 2 ;;
        --db-name)      DB_NAME="$2";       shift 2 ;;
        --db-user)      DB_USER="$2";       shift 2 ;;
        --db-pass)      DB_PASS="$2";       shift 2 ;;
        --smtp-host)    SMTP_HOST="$2";     shift 2 ;;
        --smtp-port)    SMTP_PORT="$2";     shift 2 ;;
        --smtp-from)    SMTP_FROM="$2";     shift 2 ;;
        --victim-cc)    VICTIM_CC="$2";     shift 2 ;;
        --api-port)     API_PORT="$2";      shift 2 ;;
        --api-token)    API_TOKEN="$2";     shift 2 ;;
        --log-base)     LOG_BASE="$2";      shift 2 ;;
        --install-dir)  INSTALL_DIR="$2";   shift 2 ;;
        --no-service)   DO_SERVICE=false;   shift   ;;
        --no-cron)      DO_CRON=false;      shift   ;;
        --uninstall)    DO_UNINSTALL=true;  shift   ;;
        -h|--help)      grep '^#  ' "$0" | sed 's/^#  //'; exit 0 ;;
        *) die "Unknown option: $1 (use --help)" ;;
    esac
done

# ── Uninstall Mode ────────────────────────────────────────────────────────────
if $DO_UNINSTALL; then
    step "Uninstalling ntopng-analyzer"

    systemctl stop  ntopng-analyzer-api 2>/dev/null || true
    systemctl disable ntopng-analyzer-api 2>/dev/null || true
    rm -f /etc/systemd/system/ntopng-analyzer-api.service
    systemctl daemon-reload 2>/dev/null || true

    # Remove crontab
    crontab -u "$SVC_USER" -r 2>/dev/null || true

    # Remove files
    rm -rf "$INSTALL_DIR" "$LOG_DIR"

    # Remove system user
    userdel "$SVC_USER" 2>/dev/null || true

    success "Uninstall complete. DB '$DB_NAME' was NOT dropped — remove manually if needed."
    exit 0
fi

# ── Root Check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "This script must be run as root (sudo bash setup.sh)"

# ── Generate Secrets If Needed ────────────────────────────────────────────────
gen_secret() { python3 -c "import secrets; print(secrets.token_urlsafe(32))"; }
[[ -z "$DB_PASS"   ]] && DB_PASS="$(gen_secret)"
[[ -z "$API_TOKEN" ]] && API_TOKEN="$(gen_secret)"

# ── Interactive Prompts For Required Fields ───────────────────────────────────
prompt_if_empty() {
    local var_name="$1" prompt="$2" silent="${3:-false}"
    if [[ -z "${!var_name}" ]]; then
        if $silent; then
            read -rsp "  ${prompt}: " tmp; echo
        else
            read -rp  "  ${prompt}: " tmp
        fi
        eval "$var_name=\"$tmp\""
        [[ -z "${!var_name}" ]] && die "$var_name cannot be empty"
    fi
}

step "Configuration"
prompt_if_empty SMTP_FROM   "From email address (e.g. noc@yourdomain.com)"
prompt_if_empty VICTIM_CC   "Victim CC email(s) — comma separated (e.g. noc@yourdomain.com)"

echo ""
info "Install directory : $INSTALL_DIR"
info "DB               : $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME"
info "SMTP             : $SMTP_HOST:$SMTP_PORT  from=$SMTP_FROM"
info "API              : $API_HOST:$API_PORT"
info "Log base         : $LOG_BASE"
echo ""

# ── Detect OS ─────────────────────────────────────────────────────────────────
detect_os() {
    if   [[ -f /etc/debian_version ]]; then echo "debian"
    elif [[ -f /etc/redhat-release ]]; then echo "rhel"
    elif [[ -f /etc/arch-release   ]]; then echo "arch"
    else echo "unknown"; fi
}
OS="$(detect_os)"
info "Detected OS family: $OS"

# ══════════════════════════════════════════════════════════════════════════════
step "1 / 8 — Installing system packages"
# ══════════════════════════════════════════════════════════════════════════════

install_packages_debian() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq

    # Python 3.10+ check
    PY_VERSION=$(python3 --version 2>/dev/null | awk '{print $2}' || echo "0")
    PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
    if [[ "$PY_MAJOR" -lt 3 || ( "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10 ) ]]; then
        info "Python < 3.10 found — installing 3.11 from deadsnakes PPA"
        apt-get install -y software-properties-common
        add-apt-repository -y ppa:deadsnakes/ppa
        apt-get update -qq
        apt-get install -y python3.11 python3.11-venv
        update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
    fi

    apt-get install -y \
        python3 python3-venv python3-pip \
        git curl whois \
        mariadb-client \
        postfix \
        logrotate
}

install_packages_rhel() {
    dnf install -y epel-release 2>/dev/null || yum install -y epel-release 2>/dev/null || true
    PKG_MGR="dnf"; command -v dnf &>/dev/null || PKG_MGR="yum"
    $PKG_MGR install -y \
        python3 python3-pip \
        git curl whois \
        mariadb \
        postfix \
        logrotate
    python3 -m ensurepip --upgrade 2>/dev/null || true
}

install_packages_arch() {
    pacman -Sy --noconfirm python python-pip git curl whois mariadb-clients postfix logrotate
}

case "$OS" in
    debian) install_packages_debian ;;
    rhel)   install_packages_rhel   ;;
    arch)   install_packages_arch   ;;
    *)      warn "Unknown OS — skipping package install. Ensure python3, git, whois, postfix are installed." ;;
esac

success "System packages installed"

# ══════════════════════════════════════════════════════════════════════════════
step "2 / 8 — Creating system user"
# ══════════════════════════════════════════════════════════════════════════════

if id "$SVC_USER" &>/dev/null; then
    info "User $SVC_USER already exists — skipping"
else
    useradd -r -s /sbin/nologin -d "$INSTALL_DIR" -c "ntopng Analyzer Service" "$SVC_USER"
    success "Created system user: $SVC_USER"
fi

# ══════════════════════════════════════════════════════════════════════════════
step "3 / 8 — Cloning repository"
# ══════════════════════════════════════════════════════════════════════════════

if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repo already exists — pulling latest changes"
    git -C "$INSTALL_DIR" pull --ff-only
else
    if [[ -d "$INSTALL_DIR" ]]; then
        warn "$INSTALL_DIR exists but is not a git repo — moving to ${INSTALL_DIR}.bak"
        mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
    fi
    git clone "$GITHUB_REPO" "$INSTALL_DIR"
fi
success "Repository ready at $INSTALL_DIR"

# ══════════════════════════════════════════════════════════════════════════════
step "4 / 8 — Setting up Python virtual environment"
# ══════════════════════════════════════════════════════════════════════════════

cd "$INSTALL_DIR"

python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

success "Virtual environment ready (.venv)"

# ══════════════════════════════════════════════════════════════════════════════
step "5 / 8 — Writing configuration"
# ══════════════════════════════════════════════════════════════════════════════

mkdir -p "$INSTALL_DIR/config"

cat > "$INSTALL_DIR/config/.env" <<EOF
# Auto-generated by setup.sh on $(date -u +%FT%TZ)
# Edit this file to change settings, then restart the service.

# ── Database ──────────────────────────────────────────────────────────────────
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASS}
DB_NAME=${DB_NAME}

# ── Log Paths ─────────────────────────────────────────────────────────────────
LOG_BASE_DIR=${LOG_BASE}
SCRIPT_LOG=${LOG_DIR}/analyzer.log

# ── SMTP ──────────────────────────────────────────────────────────────────────
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_TLS=${SMTP_TLS}
SMTP_USER=${SMTP_USER}
SMTP_PASS=${SMTP_PASS}
SMTP_FROM=${SMTP_FROM}
SMTP_FROM_NAME=${SMTP_FROM_NAME}

# ── Cron ──────────────────────────────────────────────────────────────────────
VICTIM_CC_EMAILS=${VICTIM_CC}

# ── API ───────────────────────────────────────────────────────────────────────
API_HOST=${API_HOST}
API_PORT=${API_PORT}
API_TOKEN=${API_TOKEN}
EOF

chmod 600 "$INSTALL_DIR/config/.env"
success "Config written to $INSTALL_DIR/config/.env"

# ══════════════════════════════════════════════════════════════════════════════
step "6 / 8 — Setting up MySQL / MariaDB"
# ══════════════════════════════════════════════════════════════════════════════

# Check if MySQL/MariaDB is running
if ! mysqladmin ping -h"$DB_HOST" -P"$DB_PORT" --silent 2>/dev/null; then
    warn "MySQL/MariaDB not reachable at $DB_HOST:$DB_PORT"
    warn "Please start MySQL/MariaDB and re-run: sudo bash $0 --no-cron --no-service"
    warn "Or run the DB setup manually (see README.md)"
else
    info "MySQL/MariaDB is reachable — setting up database"

    # Prompt for MySQL root password
    echo ""
    read -rsp "  MySQL root password (leave blank if no password): " MYSQL_ROOT_PASS
    echo ""

    MYSQL_AUTH=(-h"$DB_HOST" -P"$DB_PORT" -uroot)
    [[ -n "$MYSQL_ROOT_PASS" ]] && MYSQL_AUTH+=(-p"$MYSQL_ROOT_PASS")

    mysql "${MYSQL_AUTH[@]}" <<-SQL
        CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`
            CHARACTER SET utf8mb4
            COLLATE utf8mb4_unicode_ci;

        CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}'
            IDENTIFIED BY '${DB_PASS}';

        GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.*
            TO '${DB_USER}'@'${DB_HOST}';

        FLUSH PRIVILEGES;
SQL

    success "Database '$DB_NAME' and user '$DB_USER' created"

    # Bootstrap schema
    cd "$INSTALL_DIR"
    set -a; source "$INSTALL_DIR/config/.env"; set +a
    .venv/bin/python3 -m scripts.analyzer --bootstrap
    success "Database schema bootstrapped"
fi

# ══════════════════════════════════════════════════════════════════════════════
step "7 / 8 — Directories, permissions & log rotation"
# ══════════════════════════════════════════════════════════════════════════════

# Log directory
mkdir -p "$LOG_DIR"
touch "$LOG_DIR/analyzer.log" "$LOG_DIR/api.log" "$LOG_DIR/cron.log"

# Make run_analyzer.sh executable
chmod +x "$INSTALL_DIR/scripts/run_analyzer.sh"

# Ownership
chown -R "$SVC_USER:$SVC_USER" "$INSTALL_DIR" "$LOG_DIR"

# Grant read+write on log base (for truncating logs after processing)
# Only if the log base dir exists
if [[ -d "$LOG_BASE" ]]; then
    chown -R "$SVC_USER:$SVC_USER" "$LOG_BASE" 2>/dev/null || \
        warn "Could not chown $LOG_BASE — you may need to adjust permissions manually"
fi

# Logrotate config
cat > /etc/logrotate.d/ntopng-analyzer <<EOF
${LOG_DIR}/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 ${SVC_USER} ${SVC_USER}
    sharedscripts
    postrotate
        systemctl kill --signal=USR1 ntopng-analyzer-api 2>/dev/null || true
    endscript
}
EOF

success "Directories, permissions and logrotate configured"

# ══════════════════════════════════════════════════════════════════════════════
step "8 / 8 — Systemd service & cron"
# ══════════════════════════════════════════════════════════════════════════════

# ── Systemd Service ───────────────────────────────────────────────────────────
if $DO_SERVICE; then
    cat > /etc/systemd/system/ntopng-analyzer-api.service <<EOF
[Unit]
Description=ntopng Threat Analyzer REST API
After=network.target mysql.service mariadb.service
Wants=mysql.service mariadb.service

[Service]
Type=simple
User=${SVC_USER}
Group=${SVC_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/config/.env
Environment=PYTHONUNBUFFERED=1
ExecStart=${INSTALL_DIR}/.venv/bin/python3 -m api.server
Restart=on-failure
RestartSec=5s
StartLimitIntervalSec=60
StartLimitBurst=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${LOG_DIR}
StandardOutput=append:${LOG_DIR}/api.log
StandardError=append:${LOG_DIR}/api.log

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ntopng-analyzer-api
    systemctl restart ntopng-analyzer-api
    sleep 2

    if systemctl is-active --quiet ntopng-analyzer-api; then
        success "API service running on port $API_PORT"
    else
        warn "API service failed to start — check: journalctl -u ntopng-analyzer-api -n 50"
    fi
fi

# ── Cron Job ──────────────────────────────────────────────────────────────────
if $DO_CRON; then
    CRON_CMD="0,30 * * * * ${INSTALL_DIR}/scripts/run_analyzer.sh >> ${LOG_DIR}/cron.log 2>&1"

    # Add to crontab only if not already present
    EXISTING=$(crontab -u "$SVC_USER" -l 2>/dev/null || true)
    if echo "$EXISTING" | grep -qF "run_analyzer.sh"; then
        info "Cron job already exists — skipping"
    else
        (echo "$EXISTING"; echo "$CRON_CMD") | crontab -u "$SVC_USER" -
        success "Cron job installed (every 30 minutes)"
    fi
fi

# ══════════════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║        ntopng-analyzer installed successfully! ✓             ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Install dir   :${NC} $INSTALL_DIR"
echo -e "  ${BOLD}Log dir       :${NC} $LOG_DIR"
echo -e "  ${BOLD}Config file   :${NC} $INSTALL_DIR/config/.env"
echo -e "  ${BOLD}API URL       :${NC} http://$(hostname -I | awk '{print $1}'):$API_PORT/api/v1/"
echo -e "  ${BOLD}API Token     :${NC} $API_TOKEN"
echo -e "  ${BOLD}DB            :${NC} $DB_NAME @ $DB_HOST  (user: $DB_USER)"
echo -e "  ${BOLD}Cron          :${NC} Every 30 min as $SVC_USER"
echo ""
echo -e "  ${BOLD}Quick API test:${NC}"
echo -e "    curl -H \"Authorization: Bearer ${API_TOKEN}\" \\"
echo -e "      http://localhost:${API_PORT}/api/v1/stats"
echo ""
echo -e "  ${BOLD}Manual analyzer run:${NC}"
echo -e "    sudo -u $SVC_USER $INSTALL_DIR/scripts/run_analyzer.sh"
echo ""
echo -e "  ${BOLD}Service logs:${NC}"
echo -e "    journalctl -u ntopng-analyzer-api -f"
echo -e "    tail -f $LOG_DIR/analyzer.log"
echo ""
echo -e "  ${BOLD}Uninstall:${NC}"
echo -e "    sudo bash $INSTALL_DIR/setup.sh --uninstall"
echo ""

# Save summary to file for reference
cat > "$INSTALL_DIR/INSTALL_SUMMARY.txt" <<EOF
ntopng-analyzer Installation Summary
Generated: $(date -u +%FT%TZ)

Install dir : $INSTALL_DIR
API URL     : http://$(hostname -I | awk '{print $1}'):$API_PORT/api/v1/
API Token   : $API_TOKEN
Database    : $DB_NAME @ $DB_HOST (user: $DB_USER)
DB Password : $DB_PASS
SMTP From   : $SMTP_FROM
Victim CC   : $VICTIM_CC
Log Base    : $LOG_BASE
Log Dir     : $LOG_DIR
EOF
chmod 600 "$INSTALL_DIR/INSTALL_SUMMARY.txt"
chown "$SVC_USER:$SVC_USER" "$INSTALL_DIR/INSTALL_SUMMARY.txt"

info "Credentials saved to $INSTALL_DIR/INSTALL_SUMMARY.txt (chmod 600)"
echo ""
