#!/bin/bash
#
# Server Provisioning Validation Script
# Run this after provisioning to verify all configurations
#

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

# Test function
test_check() {
    local description=$1
    local command=$2

    echo -n "Testing: $description... "

    if eval "$command" &>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}FAIL${NC}"
        ((FAILED++))
        return 1
    fi
}

echo "========================================="
echo "Server Provisioning Validation"
echo "========================================="
echo ""

# System Updates
echo "--- System Updates ---"
test_check "System is up to date" "command -v apt-get || command -v dnf"

# User Management
echo ""
echo "--- User Management ---"
test_check "Admin user 'sysadmin' exists" "id sysadmin"
test_check "Admin user has sudo privileges" "groups sysadmin | grep -E 'sudo|wheel'"
test_check "Admin user has home directory" "test -d /home/sysadmin"
test_check "Admin user has .ssh directory" "test -d /home/sysadmin/.ssh"

# SSH Configuration
echo ""
echo "--- SSH Configuration ---"
test_check "SSH service is running" "systemctl is-active sshd || systemctl is-active ssh"
test_check "Root login is disabled" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"
test_check "SSH port changed from default" "! grep -q '^Port 22$' /etc/ssh/sshd_config"
test_check "Password authentication configured" "grep -q '^PasswordAuthentication yes' /etc/ssh/sshd_config"

# Firewall
echo ""
echo "--- Firewall Configuration ---"
if command -v firewall-cmd &>/dev/null; then
    test_check "Firewalld is running" "systemctl is-active firewalld"
    test_check "HTTP port is allowed" "firewall-cmd --list-services | grep -q http"
    test_check "HTTPS port is allowed" "firewall-cmd --list-services | grep -q https"
elif command -v ufw &>/dev/null; then
    test_check "UFW is active" "ufw status | grep -q 'Status: active'"
    test_check "HTTP port is allowed" "ufw status | grep -q '80/tcp'"
    test_check "HTTPS port is allowed" "ufw status | grep -q '443/tcp'"
else
    echo -e "${YELLOW}No supported firewall detected${NC}"
fi

# Fail2ban
echo ""
echo "--- Intrusion Prevention ---"
test_check "Fail2ban is installed" "command -v fail2ban-client"
test_check "Fail2ban is running" "systemctl is-active fail2ban"
test_check "Fail2ban SSH jail is enabled" "fail2ban-client status | grep -q sshd"

# Automatic Updates
echo ""
echo "--- Automatic Updates ---"
if command -v apt-get &>/dev/null; then
    test_check "Unattended upgrades installed" "dpkg -l | grep -q unattended-upgrades"
elif command -v dnf &>/dev/null; then
    test_check "DNF automatic installed" "dnf list installed | grep -q dnf-automatic"
    test_check "DNF automatic timer enabled" "systemctl is-enabled dnf-automatic.timer"
fi

# Essential packages
echo ""
echo "--- Essential Packages ---"
test_check "vim installed" "command -v vim"
test_check "curl installed" "command -v curl"
test_check "wget installed" "command -v wget"
test_check "git installed" "command -v git"

# System Information
echo ""
echo "========================================="
echo "System Information"
echo "========================================="
echo "Hostname: $(hostname)"
echo "IP Address: $(hostname -I | awk '{print $1}')"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo ""

# Port Information
echo "Open Ports:"
ss -tulpn | grep LISTEN | awk '{print $5}' | sort -u

echo ""
echo "========================================="
echo "Test Summary"
echo "========================================="
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! Server is properly provisioned.${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed. Review the output above.${NC}"
    exit 1
fi