#!/bin/bash
# ScoutOut Raspberry Pi Setup Script
# Run this script to set up packet capture on your Raspberry Pi

set -e

echo "===================================="
echo "ScoutOut Raspberry Pi Setup"
echo "===================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root: sudo ./setup_rpi.sh"
    exit 1
fi

# Update system
echo "Updating system packages..."
apt update && apt upgrade -y

# Install Python3 and pip if not present
echo "Installing Python dependencies..."
apt install -y python3 python3-pip python3-dev libpcap-dev

# Install Python packages
echo "Installing Python packages..."
pip3 install -r requirements_rpi.txt

# Create service directory
echo "Setting up service..."
mkdir -p /opt/scoutout
cp scoutout_capture.py /opt/scoutout/
cp requirements_rpi.txt /opt/scoutout/
chmod +x /opt/scoutout/scoutout_capture.py

# Create configuration file
cat > /opt/scoutout/config.conf << EOF
# ScoutOut Configuration
API_URL=http://172.20.0.31:5050/api
INTERFACE=eth0
FILTER=
BATCH_SIZE=5
QUEUE_SIZE=1000
EOF

# Create systemd service
cat > /etc/systemd/system/scoutout-capture.service << EOF
[Unit]
Description=ScoutOut Packet Capture Service
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/scoutout
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=/opt/scoutout/config.conf
ExecStart=/usr/bin/python3 /opt/scoutout/scoutout_capture.py --api-url \${API_URL} --interface \${INTERFACE} --filter "\${FILTER}" --batch-size \${BATCH_SIZE} --queue-size \${QUEUE_SIZE}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
echo "Enabling ScoutOut service..."
systemctl daemon-reload
systemctl enable scoutout-capture.service

echo ""
echo "===================================="
echo "Setup Complete!"
echo "===================================="
echo ""
echo "Next steps:"
echo "1. Edit /opt/scoutout/config.conf with your ScoutOut server IP"
echo "2. Start the service: sudo systemctl start scoutout-capture"
echo "3. Check status: sudo systemctl status scoutout-capture"
echo "4. View logs: sudo journalctl -u scoutout-capture -f"
echo ""
echo "Configuration file: /opt/scoutout/config.conf"
echo "Service file: /etc/systemd/system/scoutout-capture.service"
echo ""