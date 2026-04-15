#!/bin/bash

set -e

GITHUB_REPO="https://github.com/byfranke/analyze-cli"
GITHUB_RAW="https://raw.githubusercontent.com/byfranke/analyze-cli/main"
INSTALL_DIR="$HOME/.analyze-cli"
MIN_PYTHON_VERSION="3.7"

download_file() {
    local url="$1"
    local output="$2"
    
    if command -v curl >/dev/null 2>&1; then
        if [ -n "$output" ]; then
            curl -fsSL -o "$output" "$url"
        else
            curl -fsSL "$url"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if [ -n "$output" ]; then
            wget -q -O "$output" "$url"
        else
            wget -q -O - "$url"
        fi
    else
        echo "Either curl or wget is required" >&2
        return 1
    fi
}

case "$(uname -s)" in
    Darwin) OS="macos" ;;
    Linux) OS="linux" ;;
    MINGW*|MSYS*|CYGWIN*) 
        echo "Windows is not fully supported. Use WSL or Git Bash." >&2
        OS="windows"
        ;;
    *) 
        echo "Unsupported operating system: $(uname -s)" >&2
        exit 1
        ;;
esac

echo "================================="
echo "  Analyze-CLI Installation"
echo "  OS: $OS | $(uname -m)"
echo "================================="
echo ""

if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] Python 3 is required but not installed" >&2
    echo "Please install Python $MIN_PYTHON_VERSION or higher" >&2
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[OK] Python $PYTHON_VERSION found"

if ! command -v pip3 >/dev/null 2>&1 && ! command -v pip >/dev/null 2>&1; then
    echo "Installing pip..."
    python3 -m ensurepip --default-pip 2>/dev/null || {
        echo "[ERROR] pip is not installed and could not be installed automatically" >&2
        echo "Please install pip manually" >&2
        exit 1
    }
fi

echo "[OK] pip found"

if [ ! -f "requirements.txt" ] || [ ! -f "analyze-cli.py" ]; then
    echo ""
    echo "Downloading Analyze-CLI..."
    
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
    
    if command -v git >/dev/null 2>&1; then
        if [ -d "$INSTALL_DIR/.git" ]; then
            echo "Updating existing installation..."
            git pull --quiet
        else
            rm -rf "$INSTALL_DIR"/* 2>/dev/null || true
            git clone --quiet "$GITHUB_REPO.git" "$INSTALL_DIR"
        fi
        echo "[OK] Repository cloned"
    else
        echo "Downloading files directly..."
        download_file "$GITHUB_RAW/analyze-cli.py" "analyze-cli.py"
        download_file "$GITHUB_RAW/setup.py" "setup.py"
        download_file "$GITHUB_RAW/requirements.txt" "requirements.txt"
        download_file "$GITHUB_RAW/LICENSE" "LICENSE" 2>/dev/null || true
        download_file "$GITHUB_RAW/README.md" "README.md" 2>/dev/null || true
        echo "[OK] Files downloaded"
    fi
fi

WORK_DIR="${INSTALL_DIR:-$(pwd)}"
cd "$WORK_DIR"

echo ""
echo "Installing dependencies..."

install_deps() {
    local output
    output=$(pip3 install -r requirements.txt --user 2>&1) || true
    
    if echo "$output" | grep -q "Successfully installed\|already satisfied\|Requirement already"; then
        return 0
    fi
    
    if echo "$output" | grep -q "externally-managed-environment"; then
        echo ""
        echo "System uses externally managed Python (PEP 668)."
        echo "Trying: pip3 install --break-system-packages..."
        
        if pip3 install -r requirements.txt --break-system-packages 2>&1; then
            return 0
        fi
    fi
    
    return 1
}

if ! install_deps; then
    echo "[ERROR] Failed to install dependencies" >&2
    echo ""
    echo "Please try one of these options manually:"
    echo ""
    echo "Option 1: Use a virtual environment (recommended):"
    echo "  cd $WORK_DIR"
    echo "  python3 -m venv venv"
    echo "  source venv/bin/activate"
    echo "  pip install -r requirements.txt"
    echo ""
    if [ "$OS" = "linux" ]; then
        echo "Option 2: Use system packages:"
        echo "  sudo apt install python3-rich python3-cryptography python3-keyring python3-git"
        echo ""
    fi
    echo "Option 3: Force install (may affect system):"
    echo "  sudo pip3 install -r requirements.txt --break-system-packages"
    echo ""
    exit 1
fi

echo "[OK] Dependencies installed"

chmod +x analyze-cli.py setup.py

if [ -t 0 ] && { [ -w /usr/local/bin ] || command -v sudo >/dev/null 2>&1; }; then
    echo ""
    read -p "Install analyze-cli system-wide to /usr/local/bin? [y/N] " -n 1 -r </dev/tty
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -w /usr/local/bin ]; then
            ln -sf "$WORK_DIR/analyze-cli.py" /usr/local/bin/analyze-cli
        else
            sudo ln -sf "$WORK_DIR/analyze-cli.py" /usr/local/bin/analyze-cli
        fi
        echo "[OK] Installed to /usr/local/bin/analyze-cli"
    fi
fi

echo ""
echo "================================="
echo "  Installation Complete!"
echo "================================="
echo ""
echo "Installation directory: $WORK_DIR"
echo ""
echo "Next steps:"
echo "1. Configure your API token:"
echo "   cd $WORK_DIR && python3 setup.py"
echo ""
echo "2. Test the installation:"
echo "   $WORK_DIR/analyze-cli.py --version"
echo ""
echo "For help: $WORK_DIR/analyze-cli.py --help"
echo "GitHub: $GITHUB_REPO"
