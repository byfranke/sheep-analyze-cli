#!/bin/bash
set -eu

if [ -z "${HOME:-}" ] || [ "$HOME" = "/" ]; then
    echo "Refusing to run: HOME is empty or '/' (would resolve to system paths)" >&2
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIRS=("$HOME/.analyze" "$HOME/.analyze-cli")
CONFIG_DIRS=("$HOME/.analyze" "$HOME/.analyze-cli")
BACKUP_DIR="$HOME/.sheep-analyze-backup-$(date +%Y%m%d-%H%M%S)"
SYSTEM_BIN_PRIMARY="/usr/local/bin/analyze"
SYSTEM_BIN_LEGACY="/usr/local/bin/analyze-cli"
LOCAL_BIN_PRIMARY="$HOME/.local/bin/analyze"
LOCAL_BIN_LEGACY="$HOME/.local/bin/analyze-cli"
CURRENT_DIR="$(dirname "$(readlink -f "$0")")"

echo -e "${CYAN}================================="
echo "  Sheep Analyze CLI Uninstaller"
echo "=================================${NC}"
echo ""

print_info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[OK]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

ask_yes_no() {
    while true; do
        read -p "$1 (y/n): " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes (y) or no (n).";;
        esac
    done
}

check_installation() {
    local installed=false

    for dir in "${INSTALL_DIRS[@]}"; do
        if [ -d "$dir" ]; then
            print_info "Found installation directory: $dir"
            installed=true
        fi
    done

    for bin in "$SYSTEM_BIN_PRIMARY" "$SYSTEM_BIN_LEGACY" "$LOCAL_BIN_PRIMARY" "$LOCAL_BIN_LEGACY"; do
        if [ -f "$bin" ] || [ -L "$bin" ]; then
            print_info "Found binary: $bin"
            installed=true
        fi
    done

    if [ "$installed" = false ]; then
        print_warning "Sheep Analyze CLI installation not found"
        echo "Nothing to uninstall."
        exit 0
    fi
}

backup_config() {
    local found=false
    for cfg_dir in "${CONFIG_DIRS[@]}"; do
        if [ -d "$cfg_dir" ] && [ -f "$cfg_dir/config.ini" ]; then
            found=true
            break
        fi
    done
    [ "$found" = false ] && return

    echo ""
    if ! ask_yes_no "Do you want to backup your configuration files before uninstalling?"; then
        return
    fi

    print_info "Creating backup at: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    for cfg_dir in "${CONFIG_DIRS[@]}"; do
        if [ -f "$cfg_dir/config.ini" ]; then
            local label
            label="$(basename "$cfg_dir")"
            cp "$cfg_dir/config.ini" "$BACKUP_DIR/${label}.config.ini" 2>/dev/null || true
            chmod 600 "$BACKUP_DIR/${label}.config.ini" 2>/dev/null || true
            print_success "Backed up $cfg_dir/config.ini"
        fi
    done

    cat > "$BACKUP_DIR/restore.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="$(dirname "$(readlink -f "$0")")"
TARGET_DIR="$HOME/.analyze"
mkdir -p "$TARGET_DIR"
SRC=""
[ -f "$BACKUP_DIR/.analyze.config.ini" ] && SRC="$BACKUP_DIR/.analyze.config.ini"
[ -z "$SRC" ] && [ -f "$BACKUP_DIR/.analyze-cli.config.ini" ] && SRC="$BACKUP_DIR/.analyze-cli.config.ini"
if [ -n "$SRC" ]; then
    cp "$SRC" "$TARGET_DIR/config.ini"
    chmod 600 "$TARGET_DIR/config.ini"
    echo "[OK] Restored config.ini to $TARGET_DIR"
else
    echo "[ERROR] No backup found in $BACKUP_DIR"
    exit 1
fi
EOF
    chmod 700 "$BACKUP_DIR/restore.sh"
    print_success "Backup completed (mode 0700 — owner only)"
    print_info "To restore configuration later, run: $BACKUP_DIR/restore.sh"
}

remove_symlinks() {
    local removed=false

    for bin in "$SYSTEM_BIN_PRIMARY" "$SYSTEM_BIN_LEGACY"; do
        if [ -f "$bin" ] || [ -L "$bin" ]; then
            echo ""
            if ask_yes_no "Remove system-wide binary $bin?"; then
                if sudo rm -f "$bin"; then
                    print_success "Removed $bin"
                    removed=true
                else
                    print_error "Failed to remove $bin (may require sudo)"
                fi
            fi
        fi
    done

    for bin in "$LOCAL_BIN_PRIMARY" "$LOCAL_BIN_LEGACY"; do
        if [ -f "$bin" ] || [ -L "$bin" ]; then
            echo ""
            if ask_yes_no "Remove user binary $bin?"; then
                if rm -f "$bin"; then
                    print_success "Removed $bin"
                    removed=true
                else
                    print_error "Failed to remove $bin"
                fi
            fi
        fi
    done

    [ "$removed" = false ] && print_info "No symlinks to remove"
}

remove_config_dir() {
    for cfg_dir in "${CONFIG_DIRS[@]}"; do
        if [ -d "$cfg_dir" ]; then
            echo ""
            if ask_yes_no "Remove configuration directory $cfg_dir?"; then
                if rm -rf "$cfg_dir"; then
                    print_success "Removed $cfg_dir"
                else
                    print_error "Failed to remove $cfg_dir"
                fi
            fi
        fi
    done
}

clear_session_cache() {
    local uid sid
    uid=$(id -u)
    sid=$(ps -o sid= -p $$ | tr -d ' ')
    local cache="/tmp/analyze-cli-sess-${uid}-${sid}"
    if [ -f "$cache" ]; then
        rm -f "$cache" && print_success "Cleared current terminal session cache"
    fi
}

remove_dependencies() {
    echo ""
    print_warning "The following Python packages were installed by Sheep Analyze CLI:"
    echo "  - requests"
    echo "  - rich"
    echo "  - cryptography"
    echo "  - keyring"
    echo "  - GitPython"
    echo ""
    print_warning "These packages might be used by other applications"

    if ask_yes_no "Do you want to uninstall these Python packages?"; then
        print_info "Attempting to uninstall Python packages..."
        for package in requests rich cryptography keyring GitPython; do
            echo -n "  Removing $package... "
            if pip3 uninstall -y "$package" 2>/dev/null || pip uninstall -y "$package" 2>/dev/null; then
                echo -e "${GREEN}OK${NC}"
            else
                echo -e "${YELLOW}SKIP${NC} (not installed or in use)"
            fi
        done
        print_success "Package removal completed"
    else
        print_info "Skipping Python package removal"
    fi
}

remove_local_files() {
    echo ""
    print_warning "This will remove Sheep Analyze CLI files from the current directory:"
    echo "  $CURRENT_DIR"
    echo ""
    echo "Files to be removed:"
    [ -f "$CURRENT_DIR/analyze-cli.py" ] && echo "  - analyze-cli.py"
    [ -f "$CURRENT_DIR/setup.py" ] && echo "  - setup.py"
    [ -f "$CURRENT_DIR/install.sh" ] && echo "  - install.sh"
    [ -f "$CURRENT_DIR/requirements.txt" ] && echo "  - requirements.txt"
    [ -f "$CURRENT_DIR/README.md" ] && echo "  - README.md"
    [ -f "$CURRENT_DIR/LICENSE" ] && echo "  - LICENSE"
    [ -f "$CURRENT_DIR/VERSION" ] && echo "  - VERSION"
    [ -f "$CURRENT_DIR/.gitignore" ] && echo "  - .gitignore"
    echo ""

    if ask_yes_no "Remove all Sheep Analyze CLI files from current directory?"; then
        rm -f "$CURRENT_DIR/analyze-cli.py" 2>/dev/null || true
        rm -f "$CURRENT_DIR/setup.py" 2>/dev/null || true
        rm -f "$CURRENT_DIR/install.sh" 2>/dev/null || true
        rm -f "$CURRENT_DIR/requirements.txt" 2>/dev/null || true
        rm -f "$CURRENT_DIR/README.md" 2>/dev/null || true
        rm -f "$CURRENT_DIR/LICENSE" 2>/dev/null || true
        rm -f "$CURRENT_DIR/VERSION" 2>/dev/null || true
        rm -f "$CURRENT_DIR/.gitignore" 2>/dev/null || true

        print_success "Removed local files"
        print_warning "Note: This uninstall script (uninstall.sh) will remain for your records"
        print_info "You can manually delete it if desired: rm $0"
    else
        print_info "Skipping local file removal"
    fi
}

cleanup_caches() {
    echo ""
    if ask_yes_no "Clean up Python caches and temporary files?"; then
        print_info "Cleaning pip cache..."
        pip3 cache purge 2>/dev/null || pip cache purge 2>/dev/null || true

        if [ -d "$CURRENT_DIR/__pycache__" ]; then
            rm -rf "$CURRENT_DIR/__pycache__"
            print_success "Removed Python cache directory"
        fi
        print_success "Cache cleanup completed"
    fi
}

main() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root is not recommended unless removing system-wide installation"
    fi

    check_installation

    echo ""
    echo -e "${YELLOW}This will uninstall Sheep Analyze CLI from your system.${NC}"
    echo "You will be asked to confirm each step."
    echo ""

    if ! ask_yes_no "Do you want to continue with the uninstallation?"; then
        print_info "Uninstallation cancelled"
        exit 0
    fi

    backup_config
    clear_session_cache
    remove_symlinks
    remove_config_dir
    remove_dependencies
    remove_local_files
    cleanup_caches

    echo ""
    echo -e "${GREEN}================================="
    echo "  Uninstallation Complete"
    echo "=================================${NC}"
    echo ""

    if [ -d "$BACKUP_DIR" ]; then
        print_info "Your configuration was backed up to:"
        echo "  $BACKUP_DIR"
        echo ""
        print_info "To restore it later, run:"
        echo "  $BACKUP_DIR/restore.sh"
    fi

    echo ""
    print_success "Sheep Analyze CLI has been uninstalled"
    echo ""
    echo "Thank you for using Sheep Analyze CLI!"
    echo "For feedback or support: support@byfranke.com"
    echo ""
    echo "Want to come back? Reinstall any time:"
    echo "  curl -fsSL https://raw.githubusercontent.com/byfranke/sheep-analyze-cli/main/install.sh | bash"
    echo "Get an API token: https://sheep.byfranke.com/pages/store"
}

main "$@"
