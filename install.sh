#!/bin/bash

# CIVRADAR-X Installation Script
# Tactical Recon Suite Installer with Enhanced Reliability

# Color codes for better user feedback
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Function to check if running on Kali Linux
check_kali_linux() {
    if ! grep -q "Kali" /etc/os-release 2>/dev/null; then
        print_warning "This script is designed for Kali Linux. Some features may not work on other distributions."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Function to check if script is run as root (not recommended for pip installs)
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. Python packages will be installed system-wide instead of user-local."
        print_warning "Consider running as a regular user for better isolation."
    fi
}

# Function to retry apt update with fallback
apt_update_with_retry() {
    local max_attempts=3
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        print_status "Updating package lists (attempt $attempt/$max_attempts)..."
        if sudo apt update -y 2>/dev/null; then
            print_success "Package lists updated successfully"
            return 0
        else
            print_warning "apt update failed (attempt $attempt/$max_attempts)"
            if [ $attempt -eq $max_attempts ]; then
                print_error "Failed to update package lists after $max_attempts attempts"
                print_warning "Continuing with installation, but some packages may be outdated"
                return 1
            fi
            attempt=$((attempt + 1))
            sleep 2
        fi
    done
}

# Function to install packages with existence check
install_packages() {
    local packages=(
        "aircrack-ng"
        "bluez-tools"
        "arp-scan"
        "avahi-utils"
        "gpsd"
        "python3-pip"
        "python3-flask"
        "python3-flask-socketio"
        "python3-gps"
    )

    print_status "Checking and installing system packages..."

    # Check which packages are already installed
    local to_install=()
    for pkg in "${packages[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            to_install+=("$pkg")
        else
            print_status "$pkg already installed"
        fi
    done

    if [ ${#to_install[@]} -eq 0 ]; then
        print_success "All required packages are already installed"
        return 0
    fi

    print_status "Installing missing packages: ${to_install[*]}"
    if ! sudo apt install -y "${to_install[@]}"; then
        print_error "Failed to install some packages"
        return 1
    fi

    print_success "System packages installed successfully"
}

# Function to install Python packages with error handling
install_python_packages() {
    local packages=("flask" "flask-socketio" "pybluez2" "gpsd-py3")

    print_status "Installing Python packages..."

    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found. Please ensure python3-pip is installed."
        return 1
    fi

    # Use --user flag if not running as root
    local pip_flags=""
    if [[ $EUID -ne 0 ]]; then
        pip_flags="--user"
    fi

    for pkg in "${packages[@]}"; do
        print_status "Installing $pkg..."
        if pip3 install $pip_flags "$pkg" 2>/dev/null; then
            print_success "$pkg installed successfully"
        else
            print_error "Failed to install $pkg"
            return 1
        fi
    done

    print_success "All Python packages installed successfully"
}

# Function to set capabilities for airodump-ng
set_airodump_capabilities() {
    print_status "Setting capabilities for airodump-ng..."

    if sudo setcap cap_net_raw,cap_net_admin+eip /usr/sbin/airodump-ng 2>/dev/null; then
        print_success "Capabilities set for airodump-ng"
    else
        print_warning "Failed to set capabilities for airodump-ng (may require manual setup)"
    fi
}

# Function to create log directory
create_log_directory() {
    print_status "Creating log directory..."

    if sudo mkdir -p /opt/civradar-x/logs 2>/dev/null; then
        print_success "Log directory created at /opt/civradar-x/logs"
    else
        print_error "Failed to create log directory"
        return 1
    fi
}

# Function to verify installation
verify_installation() {
    print_status "Verifying installation..."

    local errors=0

    # Check Python packages
    for pkg in flask flask-socketio pybluez2 gpsd_py3; do
        if python3 -c "import $pkg" 2>/dev/null; then
            print_success "Python package $pkg is available"
        else
            print_error "Python package $pkg is not available"
            errors=$((errors + 1))
        fi
    done

    # Check system commands
    for cmd in aircrack-ng arp-scan avahi-browse gpsd; do
        if command -v "$cmd" &> /dev/null; then
            print_success "Command $cmd is available"
        else
            print_error "Command $cmd is not available"
            errors=$((errors + 1))
        fi
    done

    if [ $errors -eq 0 ]; then
        print_success "Installation verification passed"
        return 0
    else
        print_warning "Installation verification failed with $errors errors"
        return 1
    fi
}

# Cleanup function
cleanup() {
    print_status "Cleaning up..."
    # Add any cleanup tasks here if needed
}

# Trap for cleanup on exit
trap cleanup EXIT

# Main installation function
main() {
    echo -e "${GREEN}☠️  Installing CIVRADAR-X — Tactical Recon Suite${NC}"
    echo

    # Pre-installation checks
    check_kali_linux
    check_root

    # Installation steps
    apt_update_with_retry
    install_packages || exit 1
    install_python_packages || exit 1
    set_airodump_capabilities
    create_log_directory || exit 1

    # Verification
    verify_installation

    echo
    print_success "Installation complete!"
    echo
    echo "To run CIVRADAR-X:"
    echo "  cd /path/to/civradar-x"
    echo "  sudo PYTHONPATH=/path/to/civradar-x python3 -m civradar.app"
    echo
    echo "For more information, see README.md"
}

# Run main function
main "$@"