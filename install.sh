#!/bin/bash

set -e

GITHUB_REPO="https://github.com/byfranke/analyze-cli"
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

echo ""
echo "Installing dependencies..."

install_deps() {
    if pip3 install -r requirements.txt --user 2>&1 | grep -q "Successfully installed\|already satisfied"; then
        return 0
    fi
    
    if pip3 install -r requirements.txt --user 2>&1 | grep -q "externally-managed-environment"; then
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

echo ""
echo "================================="
echo "  Installation Complete!"
echo "================================="
echo ""
echo "Next steps:"
echo "1. Configure your API token:"
echo "   python3 setup.py"
echo ""
echo "2. Test the installation:"
echo "   ./analyze-cli.py --version"
echo ""
echo "For help: ./analyze-cli.py --help"
echo "GitHub: $GITHUB_REPO"
