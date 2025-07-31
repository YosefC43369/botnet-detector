#!/bin/bash

# Botnet Detector Installation Script for Kali Linux
# Usage: ./install.sh

set -e

echo "🔍 Installing Advanced Botnet Detection Script"
echo "=============================================="

# Check if running on Kali Linux
if ! grep -q "kali" /etc/os-release 2>/dev/null; then
    echo "⚠️  Warning: This script is optimized for Kali Linux"
    echo "Some features may not work properly on other distributions"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo "⚠️  Running as root. Some pip installations may fail."
    echo "Consider running as regular user and using sudo when needed."
fi

# Update system packages
echo "📦 Updating system packages..."
sudo apt update

# Install system dependencies
echo "🛠️  Installing system dependencies..."
sudo apt install -y python3 python3-pip python3-dev build-essential

# Check for required tools
echo "🔧 Checking required tools..."
REQUIRED_TOOLS=("nmap" "dig" "curl")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    else
        echo "✅ $tool found"
    fi
done

# Install missing tools
if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo "📥 Installing missing tools: ${MISSING_TOOLS[*]}"
    
    # Map tools to packages
    declare -A TOOL_PACKAGES
    TOOL_PACKAGES[nmap]="nmap"
    TOOL_PACKAGES[dig]="dnsutils"
    TOOL_PACKAGES[curl]="curl"
    
    PACKAGES_TO_INSTALL=()
    for tool in "${MISSING_TOOLS[@]}"; do
        if [[ -n "${TOOL_PACKAGES[$tool]}" ]]; then
            PACKAGES_TO_INSTALL+=("${TOOL_PACKAGES[$tool]}")
        fi
    done
    
    if [ ${#PACKAGES_TO_INSTALL[@]} -ne 0 ]; then
        sudo apt install -y "${PACKAGES_TO_INSTALL[@]}"
    fi
fi

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install --user -r requirements.txt
else
    echo "⚠️  requirements.txt not found. Installing basic dependencies..."
    pip3 install --user scapy psutil requests python-whois dnspython
fi

# Make script executable
echo "🔐 Setting permissions..."
chmod +x botnet_detector.py

# Create output directory
echo "📁 Creating output directory..."
mkdir -p output

# Test installation
echo "🧪 Testing installation..."
python3 -c "
import scapy.all
import psutil  
import requests
import whois
import dns.resolver
print('✅ All Python modules imported successfully')
"

# Check network capabilities
echo "🌐 Checking network capabilities..."
if python3 -c "
import socket
try:
    socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    print('✅ Raw socket access available')
except:
    print('⚠️  Raw socket access limited - run with sudo for full functionality')
" 2>/dev/null; then
    :
else
    echo "⚠️  Limited network access - run with sudo for packet capture"
fi

echo ""
echo "🎉 Installation completed successfully!"
echo ""
echo "🚀 Usage examples:"
echo "  # General monitoring (requires sudo)"
echo "  sudo python3 botnet_detector.py --mode general --duration 300"
echo ""
echo "  # Website analysis"
echo "  sudo python3 botnet_detector.py --mode website --target https://example.com"
echo ""
echo "  # Quick scan"
echo "  sudo python3 botnet_detector.py --mode scan --target example.com"
echo ""
echo "📚 For more information, check README.md"
echo ""
echo "⚠️  Remember: Always use this tool responsibly and legally!"
echo "   Only scan systems you own or have explicit permission to test."