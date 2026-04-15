#!/bin/bash
# Analyze-CLI Uninstall Script
# Copyright (c) 2026 byFranke - Security Solutions
#
# This script removes Analyze-CLI and its associated files from your system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables
INSTALL_DIR="$HOME/.analyze-cli"
BACKUP_DIR="$HOME/.analyze-cli-backup-$(date +%Y%m%d-%H%M%S)"
SYSTEM_BIN="/usr/local/bin/analyze-cli"
LOCAL_BIN="$HOME/.local/bin/analyze-cli"

echo -e "${CYAN}================================="
echo "  Analyze-CLI Uninstaller"
echo "=================================${NC}"
echo ""

# Function to print colored messages
print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to ask yes/no questions
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

# Check if Analyze-CLI is installed
check_installation() {
    local installed=false

    if [ -d "$INSTALL_DIR" ]; then
        print_info "Found installation directory: $INSTALL_DIR"
        installed=true
    fi

    if [ -f "$SYSTEM_BIN" ]; then
        print_info "Found system-wide installation: $SYSTEM_BIN"
        installed=true
    fi

    if [ -f "$LOCAL_BIN" ]; then
        print_info "Found local bin installation: $LOCAL_BIN"
        installed=true
    fi

    if [ "$installed" = false ]; then
        print_warning "Analyze-CLI installation not found"
        echo "Nothing to uninstall."
        exit 0
    fi
}

# Backup configuration files
backup_config() {
    if [ -d "$INSTALL_DIR" ]; then
        echo ""
        if ask_yes_no "Do you want to backup your configuration files before uninstalling?"; then
            print_info "Creating backup at: $BACKUP_DIR"
            mkdir -p "$BACKUP_DIR"

            if [ -f "$INSTALL_DIR/config.ini" ]; then
                cp "$INSTALL_DIR/config.ini" "$BACKUP_DIR/" 2>/dev/null || true
                print_success "Backed up config.ini"
            fi

            if [ -f "$INSTALL_DIR/.key" ]; then
                cp "$INSTALL_DIR/.key" "$BACKUP_DIR/" 2>/dev/null || true
                print_success "Backed up encryption key"
            fi

            cat > "$BACKUP_DIR/restore.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="$(dirname "$(readlink -f "$0")")"
INSTALL_DIR="$HOME/.analyze-cli"

echo "Restoring Analyze-CLI configuration..."
echo "Note: You need to reinstall Analyze-CLI first:"
echo "  curl -fsSL https://raw.githubusercontent.com/byfranke/analyze-cli/main/install.sh | bash"
echo ""

if [ ! -d "$INSTALL_DIR" ]; then
    echo "[ERROR] Installation directory not found. Please reinstall first."
    exit 1
fi

if [ -f "$BACKUP_DIR/config.ini" ]; then
    cp "$BACKUP_DIR/config.ini" "$INSTALL_DIR/"
    chmod 600 "$INSTALL_DIR/config.ini"
    echo "[OK] Restored config.ini"
fi

if [ -f "$BACKUP_DIR/.key" ]; then
    cp "$BACKUP_DIR/.key" "$INSTALL_DIR/"
    chmod 600 "$INSTALL_DIR/.key"
    echo "[OK] Restored encryption key"
fi

echo "Configuration restored successfully!"
EOF
            chmod +x "$BACKUP_DIR/restore.sh"

            print_success "Backup completed"
            print_info "To restore configuration later, run: $BACKUP_DIR/restore.sh"
        fi
    fi
}

# Remove symlinks
remove_symlinks() {
    local removed=false

    if [ -f "$SYSTEM_BIN" ]; then
        echo ""
        if ask_yes_no "Remove system-wide symlink from /usr/local/bin?"; then
            if sudo rm -f "$SYSTEM_BIN"; then
                print_success "Removed $SYSTEM_BIN"
                removed=true
            else
                print_error "Failed to remove $SYSTEM_BIN (may require sudo)"
            fi
        fi
    fi

    if [ -f "$LOCAL_BIN" ] || [ -L "$LOCAL_BIN" ]; then
        echo ""
        if ask_yes_no "Remove symlink from ~/.local/bin?"; then
            if rm -f "$LOCAL_BIN"; then
                print_success "Removed $LOCAL_BIN"
                removed=true
            else
                print_error "Failed to remove $LOCAL_BIN"
            fi
        fi
    fi

    if [ "$removed" = false ]; then
        print_info "No symlinks to remove"
    fi
}

# Remove installation directory
remove_install_dir() {
    if [ -d "$INSTALL_DIR" ]; then
        echo ""
        print_warning "This will remove the entire installation directory:"
        echo "  $INSTALL_DIR"
        echo ""
        echo "Contents:"
        ls -la "$INSTALL_DIR" 2>/dev/null | head -15
        echo ""

        if ask_yes_no "Remove installation directory (~/.analyze-cli)?"; then
            if rm -rf "$INSTALL_DIR"; then
                print_success "Removed installation directory"
            else
                print_error "Failed to remove installation directory"
            fi
        fi
    fi
}

# Remove Python dependencies
remove_dependencies() {
    echo ""
    print_warning "The following Python packages were installed by Analyze-CLI:"
    echo "  - requests"
    echo "  - rich"
    echo "  - configparser"
    echo "  - cryptography"
    echo "  - keyring"
    echo "  - getpass4"
    echo "  - GitPython"
    echo ""
    print_warning "These packages might be used by other applications"

    if ask_yes_no "Do you want to uninstall these Python packages?"; then
        print_info "Attempting to uninstall Python packages..."

        # Try to uninstall packages
        packages="requests rich configparser cryptography keyring getpass4 GitPython"

        for package in $packages; do
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

# Clean up PATH entries (optional info)
show_path_cleanup_info() {
    echo ""
    print_info "If you added ~/.local/bin to your PATH, you may want to remove it from:"
    echo "  - ~/.bashrc"
    echo "  - ~/.zshrc"
    echo "  - ~/.profile"
    echo ""
    echo "Look for lines containing: export PATH=\"\$HOME/.local/bin:\$PATH\""
}

# Clean up system caches
cleanup_caches() {
    echo ""
    if ask_yes_no "Clean up Python caches?"; then
        print_info "Cleaning pip cache..."
        pip3 cache purge 2>/dev/null || pip cache purge 2>/dev/null || true
        print_success "Cache cleanup completed"
    fi
}

# Main uninstall process
main() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root is not recommended unless removing system-wide installation"
    fi

    check_installation

    echo ""
    echo -e "${YELLOW}This will uninstall Analyze-CLI from your system.${NC}"
    echo "You will be asked to confirm each step."
    echo ""

    if ! ask_yes_no "Do you want to continue with the uninstallation?"; then
        print_info "Uninstallation cancelled"
        exit 0
    fi

    backup_config

    remove_symlinks

    remove_dependencies

    remove_install_dir

    cleanup_caches

    show_path_cleanup_info

    # Final message
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
    print_success "Analyze-CLI has been uninstalled"
    echo ""
    echo "Thank you for using Analyze-CLI!"
    echo "For feedback or support: support@byfranke.com"
}

# Run main function
main "$@"
