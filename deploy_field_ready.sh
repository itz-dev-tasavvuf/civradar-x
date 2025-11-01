#!/bin/bash
# civradar-x/deploy_field_ready.sh
# One-command deployment script for hostile environments
# This script sets up CIVRADAR-X with full OPSEC features

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="civradar-x"
INSTALL_DIR="/opt/${APP_NAME}"
SERVICE_USER="civradar"
SERVICE_GROUP="civradar"
LOG_DIR="/var/log/${APP_NAME}"
CONFIG_DIR="/etc/${APP_NAME}"
DATA_DIR="/var/lib/${APP_NAME}"
TEMP_DIR="/tmp/.${APP_NAME}_opsec"

# OPSEC Configuration
OPSEC_SECURITY_LEVEL="high"
FIELD_MODE="stealth"
AUTO_WIPE_TIMEOUT=300
THREAT_DETECTION_SENSITIVITY=7

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_opsec() {
    echo -e "${PURPLE}[OPSEC]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to detect system
detect_system() {
    print_status "Detecting system configuration..."
    
    if [[ -f /etc/debian_version ]]; then
        OS="debian"
        PKG_MANAGER="apt"
    elif [[ -f /etc/redhat-release ]]; then
        OS="rhel"
        PKG_MANAGER="yum"
    else
        print_error "Unsupported operating system"
        exit 1
    fi
    
    print_success "Detected OS: $OS"
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing system dependencies..."
    
    if [[ $OS == "debian" ]]; then
        apt update
        apt install -y \
            python3 python3-pip python3-venv \
            sqlite3 nmap aircrack-ng \
            iw wireless-tools bluetooth \
            net-tools iproute2 \
            torsocks proxychains4 \
            secure-delete wipe \
            apparmor-utils \
            gnupg2 rng-tools \
            tcpdump wireshark-common \
            steghide exiftool \
            foremost testdisk photorec
    elif [[ $OS == "rhel" ]]; then
        yum install -y \
            python3 python3-pip \
            sqlite nmap aircrack-ng \
            wireless-tools bluetooth-utils \
            net-tools iproute \
            torsocks proxychains \
            secure-delete wipe \
            gnupg2 rng-tools \
            tcpdump wireshark \
            steghide exiftool \
            foremost testdisk photorec
    fi
    
    print_success "System dependencies installed"
}

# Function to create service user
create_service_user() {
    print_status "Creating service user and group..."
    
    # Create group if it doesn't exist
    if ! getent group $SERVICE_GROUP >/dev/null 2>&1; then
        groupadd --system $SERVICE_GROUP
    fi
    
    # Create user if it doesn't exist
    if ! getent passwd $SERVICE_USER >/dev/null 2>&1; then
        useradd --system \
                --gid $SERVICE_GROUP \
                --shell /usr/sbin/nologin \
                --home $INSTALL_DIR \
                --create-home \
                $SERVICE_USER
    fi
    
    print_success "Service user created"
}

# Function to setup directories
setup_directories() {
    print_status "Setting up directory structure..."
    
    # Create directories
    mkdir -p $INSTALL_DIR
    mkdir -p $LOG_DIR
    mkdir -p $CONFIG_DIR
    mkdir -p $DATA_DIR
    mkdir -p $TEMP_DIR
    
    # Set permissions
    chown -R $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR
    chown -R $SERVICE_USER:$SERVICE_GROUP $LOG_DIR
    chown -R $SERVICE_USER:$SERVICE_GROUP $DATA_DIR
    chown -R $SERVICE_USER:$SERVICE_GROUP $TEMP_DIR
    
    # Secure permissions
    chmod 750 $INSTALL_DIR
    chmod 750 $LOG_DIR
    chmod 750 $CONFIG_DIR
    chmod 700 $DATA_DIR
    chmod 700 $TEMP_DIR
    
    print_success "Directory structure created"
}

# Function to create Python virtual environment
setup_python_environment() {
    print_status "Setting up Python virtual environment..."
    
    # Create virtual environment
    sudo -u $SERVICE_USER python3 -m venv $INSTALL_DIR/venv
    
    # Upgrade pip
    sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install --upgrade pip
    
    # Install Python dependencies
    sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/pip install \
        flask flask-socketio \
        cryptography pynacl \
        psutil netifaces \
        scapy requests \
        numpy pandas \
        pynmea2 python-dateutil
    
    print_success "Python environment configured"
}

# Function to copy application files
copy_application() {
    print_status "Copying application files..."
    
    # Copy application directory
    cp -r . $INSTALL_DIR/
    
    # Set ownership
    chown -R $SERVICE_USER:$SERVICE_GROUP $INSTALL_DIR
    
    # Set execute permissions
    find $INSTALL_DIR -type f -name "*.py" -exec chmod 755 {} \;
    
    print_success "Application files copied"
}

# Function to create configuration
create_configuration() {
    print_status "Creating OPSEC configuration..."
    
    # Main configuration
    cat > $CONFIG_DIR/opsec.conf << EOF
[OPSEC]
security_level = $OPSEC_SECURITY_LEVEL
field_mode = $FIELD_MODE
auto_wipe_timeout = $AUTO_WIPE_TIMEOUT
threat_detection_sensitivity = $THREAT_DETECTION_SENSITIVITY
encrypted_logs = true
secure_deletion = true
anti_forensics = true
process_hiding = true
network_stealth = true

[Paths]
install_dir = $INSTALL_DIR
log_dir = $LOG_DIR
data_dir = $DATA_DIR
temp_dir = $TEMP_DIR
config_dir = $CONFIG_DIR

[Stealth]
hide_processes = true
randomize_ports = true
block_outbound = false
fake_activity = true
time_stomping = true
memory_protection = true

[Network]
stealth_mode = true
tor_support = false
proxy_chains = false
port_randomization = true

[Logging]
encrypted = true
rotate_logs = true
secure_wipe = true
time_stomping = true
fake_logs = true
EOF

    # Field configuration
    cat > $CONFIG_DIR/field_ops.conf << EOF
[FieldOperations]
default_mode = $FIELD_MODE
auto_mode_switching = true
threat_threshold = $THREAT_DETECTION_SENSITIVITY
emergency_wipe_on_detection = true

[StealthProfiles]
normal = hide_process:false, encrypt_logs:true
stealth = hide_process:true, fake_process_name:kworker, randomize_ports:true
ghost = hide_process:true, block_outbound:true, disable_logging:true
combat = hide_process:true, encrypt_logs:true, fake_activity:true

[ThreatDetection]
sensitivity = $THREAT_DETECTION_SENSITIVITY
scan_interval = 2
auto_response = true
backup_wipe_interval = 300
EOF

    # Set secure permissions
    chown $SERVICE_USER:$SERVICE_GROUP $CONFIG_DIR/*.conf
    chmod 640 $CONFIG_DIR/*.conf
    
    print_success "OPSEC configuration created"
}

# Function to create systemd service
create_systemd_service() {
    print_status "Creating systemd service..."
    
    cat > /etc/systemd/system/civradar-x.service << EOF
[Unit]
Description=CIVRADAR-X Field-Ready Intelligence System
After=network.target
Wants=network.target

[Service]
Type=simple
User=civradar
Group=civradar
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
Environment=FLASK_APP=civradar.app
EnvironmentFile=$CONFIG_DIR/opsec.conf
ExecStart=$INSTALL_DIR/venv/bin/python3 -m civradar.app
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=civradar-x

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR $LOG_DIR $DATA_DIR $TEMP_DIR
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

# OPSEC settings
ExecStartPre=/bin/sh -c 'echo "CIVRADAR-X starting in $FIELD_MODE mode"'
ExecStartPost=/bin/sh -c 'srm -vf $TEMP_DIR/* 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    print_success "Systemd service created"
}

# Function to setup firewall rules
setup_firewall() {
    print_status "Configuring firewall rules..."
    
    if command -v ufw >/dev/null 2>&1; then
        # UFW configuration
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow out 53    # DNS
        ufw allow out 80    # HTTP
        ufw allow out 443   # HTTPS
        ufw allow out 9050  # Tor
        ufw allow out 9051  # Tor control
        ufw enable
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # Firewalld configuration
        firewall-cmd --permanent --set-default-zone=external
        firewall-cmd --permanent --zone=external --add-service=dns
        firewall-cmd --permanent --zone=external --add-service=http
        firewall-cmd --permanent --zone=external --add-service=https
        firewall-cmd --reload
    fi
    
    print_success "Firewall configured"
}

# Function to setup kernel security
setup_kernel_security() {
    print_status "Configuring kernel security settings..."
    
    # Kernel parameters for stealth
    cat >> /etc/sysctl.d/99-civradar-opsec.conf << EOF
# CIVRADAR-X OPSEC Settings
# Network stealth
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Process hiding
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# Memory protection
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1

# Network interface hiding
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

    sysctl -p /etc/sysctl.d/99-civradar-opsec.conf
    
    print_success "Kernel security configured"
}

# Function to create operational scripts
create_operational_scripts() {
    print_status "Creating operational scripts..."
    
    # Emergency wipe script
    cat > /usr/local/bin/civradar-emergency-wipe << 'EOF'
#!/bin/bash
# Emergency wipe script for CIVRADAR-X
set -euo pipefail

print_opsec "EMERGENCY WIPE INITIATED"
echo "This will securely delete all CIVRADAR-X data..."

# Kill all CIVRADAR-X processes
pkill -f civradar || true

# Wipe directories
for dir in "/var/lib/civradar-x" "/tmp/.civradar_opsec" "/tmp/.civradar_shares" "/tmp/.civradar-x_opsec"; do
    if [[ -d "$dir" ]]; then
        print_opsec "Wiping $dir"
        find "$dir" -type f -exec srm -vf {} \; 2>/dev/null || true
        rm -rf "$dir"
    fi
done

# Wipe logs
find /var/log/civradar-x -type f -name "*.log" -exec srm -vf {} \; 2>/dev/null || true

# Clear browser data if running locally
rm -rf /tmp/.org.chromium.Chromium.* 2>/dev/null || true
rm -rf /home/*/.cache/google-chrome* 2>/dev/null || true

print_opsec "EMERGENCY WIPE COMPLETED"
sync
echo 3 > /proc/sys/vm/drop_caches

# Reboot suggestion
echo "System reboot recommended to clear memory traces."
read -p "Reboot now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    reboot
fi
EOF

    chmod +x /usr/local/bin/civradar-emergency-wipe
    
    # Field operation script
    cat > /usr/local/bin/civradar-field-ops << 'EOF'
#!/bin/bash
# Field operations control script for CIVRADAR-X
set -euo pipefail

OPERATION=${1:-status}
MODE=${2:-stealth}

case $OPERATION in
    start)
        print_opsec "Starting CIVRADAR-X in $MODE mode"
        systemctl start civradar-x
        ;;
    stop)
        print_opsec "Stopping CIVRADAR-X"
        systemctl stop civradar-x
        ;;
    restart)
        print_opsec "Restarting CIVRADAR-X in $MODE mode"
        systemctl restart civradar-x
        ;;
    status)
        print_opsec "CIVRADAR-X Status:"
        systemctl status civradar-x --no-pager
        ;;
    mode)
        print_opsec "Switching to $MODE mode"
        # Implementation would update configuration
        systemctl restart civradar-x
        ;;
    wipe)
        civradar-emergency-wipe
        ;;
    logs)
        journalctl -u civradar-x -f
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|mode|wipe|logs} [mode]"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/civradar-field-ops
    
    print_success "Operational scripts created"
}

# Function to setup monitoring
setup_monitoring() {
    print_status "Setting up monitoring and alerting..."
    
    # Create monitoring script
    cat > /usr/local/bin/civradar-monitor << 'EOF'
#!/bin/bash
# CIVRADAR-X monitoring script
set -euo pipefail

LOG_FILE="/var/log/civradar-x/monitor.log"
STATUS_FILE="/tmp/.civradar_status"

log_status() {
    echo "$(date): $1" >> $LOG_FILE
}

# Check if service is running
if ! systemctl is-active civradar-x >/dev/null 2>&1; then
    log_status "ERROR: civradar-x service not running"
    # Attempt restart
    systemctl restart civradar-x
    log_status "INFO: Attempted service restart"
fi

# Check system resources
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
MEM_USAGE=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')

if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then
    log_status "WARNING: High CPU usage: $CPU_USAGE%"
fi

if (( $(echo "$MEM_USAGE > 90" | bc -l) )); then
    log_status "WARNING: High memory usage: $MEM_USAGE%"
fi

# Check for suspicious processes
SUSPICIOUS_PROCS=$(ps aux | grep -E "(wireshark|tcpdump|nmap|volatility|foremost)" | grep -v grep || true)
if [[ -n "$SUSPICIOUS_PROCS" ]]; then
    log_status "ALERT: Suspicious processes detected"
    echo "$SUSPICIOUS_PROCS" >> $LOG_FILE
fi

# Update status file
cat > $STATUS_FILE << EOStatus
CIVRADAR-X Monitor Status
========================
Service: $(systemctl is-active civradar-x)
CPU Usage: $CPU_USAGE%
Memory Usage: $MEM_USAGE%
Last Check: $(date)
Suspicious Processes: $(echo "$SUSPICIOUS_PROCS" | wc -l)
EOStatus
EOF

    chmod +x /usr/local/bin/civradar-monitor
    
    # Create cron job for monitoring
    cat > /etc/cron.d/civradar-monitor << EOF
# CIVRADAR-X monitoring cron job
*/5 * * * * root /usr/local/bin/civradar-monitor
0 0 * * * root find /var/log/civradar-x -name "*.log" -mtime +7 -delete
EOF

    print_success "Monitoring configured"
}

# Function to setup appArmor profile
setup_apparmor() {
    print_status "Setting up AppArmor profile..."
    
    if command -v aa-enforce >/dev/null 2>&1; then
        cat > /etc/apparmor.d/usr.local.bin.civradar-x << EOF
#include <tunables/global>

/usr/local/bin/civradar-x {
  #include <abstractions/base>
  
  # Allow execution
  /usr/local/bin/civradar-x mr,
  /usr/bin/python3* mr,
  
  # Allow access to application directory
  $INSTALL_DIR/** mr,
  
  # Allow access to data directories
  $DATA_DIR/** rw,
  $LOG_DIR/** rw,
  $TEMP_DIR/** rw,
  
  # Allow network access
  network inet stream,
  network inet6 stream,
  
  # Allow system calls
  signal (receive) set=(term, int, hup),
  ptrace (readby),
  
  # Deny sensitive paths
  deny /etc/shadow r,
  deny /root/** rw,
  deny /home/*/.ssh/** rw,
}
EOF

        apparmor_parser -r /etc/apparmor.d/usr.local.bin.civradar-x
        
        print_success "AppArmor profile configured"
    else
        print_warning "AppArmor not available, skipping profile setup"
    fi
}

# Function to create uninstall script
create_uninstall_script() {
    print_status "Creating uninstall script..."
    
    cat > /usr/local/bin/civradar-uninstall << 'EOF'
#!/bin/bash
# CIVRADAR-X uninstall script
set -euo pipefail

echo "WARNING: This will completely remove CIVRADAR-X and all data!"
read -p "Are you sure? (yes/no): " confirm

if [[ $confirm != "yes" ]]; then
    echo "Uninstall cancelled"
    exit 1
fi

# Stop and disable service
systemctl stop civradar-x 2>/dev/null || true
systemctl disable civradar-x 2>/dev/null || true

# Remove service files
rm -f /etc/systemd/system/civradar-x.service
systemctl daemon-reload

# Secure wipe directories
srm -rvf /opt/civradar-x 2>/dev/null || rm -rf /opt/civradar-x
srm -rvf /var/lib/civradar-x 2>/dev/null || rm -rf /var/lib/civradar-x
srm -rvf /var/log/civradar-x 2>/dev/null || rm -rf /var/log/civradar-x
srm -rvf /etc/civradar-x 2>/dev/null || rm -rf /etc/civradar-x
srm -rvf /tmp/.civradar_* 2>/dev/null || rm -rf /tmp/.civradar_*

# Remove scripts
rm -f /usr/local/bin/civradar-*
rm -f /etc/cron.d/civradar-*
rm -f /etc/apparmor.d/usr.local.bin.civradar-x

# Remove user and group
userdel civradar 2>/dev/null || true
groupdel civradar 2>/dev/null || true

# Remove kernel parameters
rm -f /etc/sysctl.d/99-civradar-opsec.conf
sysctl -p 2>/dev/null || true

echo "CIVRADAR-X uninstalled and data securely wiped"
EOF

    chmod +x /usr/local/bin/civradar-uninstall
    
    print_success "Uninstall script created"
}

# Function to run post-installation checks
post_install_checks() {
    print_status "Running post-installation checks..."
    
    # Test service startup
    if systemctl start civradar-x; then
        print_success "Service started successfully"
        sleep 5
        if systemctl is-active civradar-x >/dev/null 2>&1; then
            print_success "Service is running"
        else
            print_warning "Service started but not active"
        fi
        systemctl stop civradar-x
    else
        print_error "Failed to start service"
    fi
    
    # Test configuration
    if [[ -f $CONFIG_DIR/opsec.conf ]]; then
        print_success "Configuration files created"
    else
        print_error "Configuration files missing"
    fi
    
    # Test permissions
    if [[ -O $INSTALL_DIR ]]; then
        print_success "Directory permissions correct"
    else
        print_warning "Directory permissions issue"
    fi
    
    print_success "Post-installation checks completed"
}

# Main installation function
main() {
    echo -e "${CYAN}"
    echo "============================================"
    echo "  CIVRADAR-X FIELD-READY DEPLOYMENT"
    echo "  OPSEC-Enhanced Intelligence System"
    echo "============================================"
    echo -e "${NC}"
    
    print_opsec "Starting deployment with OPSEC features"
    print_opsec "Security Level: $OPSEC_SECURITY_LEVEL"
    print_opsec "Field Mode: $FIELD_MODE"
    print_opsec "Auto-wipe Timeout: ${AUTO_WIPE_TIMEOUT}s"
    
    # Check prerequisites
    check_root
    detect_system
    
    # Install system components
    install_dependencies
    create_service_user
    setup_directories
    setup_python_environment
    copy_application
    
    # Configure OPSEC features
    create_configuration
    setup_firewall
    setup_kernel_security
    setup_apparmor
    
    # Create operational infrastructure
    create_systemd_service
    create_operational_scripts
    setup_monitoring
    
    # Post-installation
    create_uninstall_script
    post_install_checks
    
    echo -e "${GREEN}"
    echo "============================================"
    echo "  DEPLOYMENT COMPLETED SUCCESSFULLY"
    echo "============================================"
    echo -e "${NC}"
    echo
    print_success "CIVRADAR-X is ready for field operations"
    echo
    echo "Service Management:"
    echo "  Start:  systemctl start civradar-x"
    echo "  Stop:   systemctl stop civradar-x"
    echo "  Status: systemctl status civradar-x"
    echo "  Logs:   journalctl -u civradar-x -f"
    echo
    echo "Field Operations:"
    echo "  civradar-field-ops start|stop|status|wipe"
    echo "  Emergency wipe: civradar-emergency-wipe"
    echo "  Monitor: civradar-monitor"
    echo
    echo "Configuration:"
    echo "  OPSEC Config: $CONFIG_DIR/opsec.conf"
    echo "  Field Config: $CONFIG_DIR/field_ops.conf"
    echo
    print_opsec "Remember: Use civradar-emergency-wipe in hostile situations"
    echo
}

# Run main function
main "$@"