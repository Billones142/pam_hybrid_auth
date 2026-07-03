#!/bin/bash

# Configuration
SERVICE_NAME="pam_test_password_fingerprint"
PAM_CONF_PATH="/etc/pam.d/$SERVICE_NAME"
PAM_MODULE_NAME="pam_password_fingerprint.so"

# Check if pamtester is installed
if ! command -v pamtester &> /dev/null; then
    echo "Error: 'pamtester' is not installed."
    echo "Please install it to run the tests. For example:"
    echo "  - Debian/Ubuntu: sudo apt install pamtester"
    echo "  - Arch Linux:    yay -S pamtester"
    echo "  - Fedora/RHEL:   sudo dnf install pamtester"
    exit 1
fi

# Detect current user
TEST_USER=$(logname 2>/dev/null || echo $USER)

# Detect PAM module location
if [ -f "target/release/libpam_password_fingerprint.so" ]; then
    PAM_MODULE_PATH="$(pwd)/target/release/libpam_password_fingerprint.so"
elif [ -f "/lib/x86_64-linux-gnu/security/$PAM_MODULE_NAME" ]; then
    PAM_MODULE_PATH="/lib/x86_64-linux-gnu/security/$PAM_MODULE_NAME"
elif [ -f "/lib/security/$PAM_MODULE_NAME" ]; then
    PAM_MODULE_PATH="/lib/security/$PAM_MODULE_NAME"
else
    echo "Warning: PAM module has not been built or installed yet."
    echo "Please run 'make' to build it first."
    exit 1
fi

echo "To test the PAM module, we need to create a test configuration at $PAM_CONF_PATH."
echo "This requires sudo privileges. Creating config..."

# Check for argument to show stars
SHOW_STARS_ARG=""
if [ "$1" == "show_stars" ]; then
    SHOW_STARS_ARG="show_stars"
    echo "Enabling password typing feedback with asterisks."
fi

# Setup temporary PAM config
sudo bash -c "cat > $PAM_CONF_PATH" <<EOF
# PAM configuration for testing pam_password_fingerprint
auth required $PAM_MODULE_PATH $SHOW_STARS_ARG tries=4
account required pam_permit.so
EOF

if [ $? -ne 0 ]; then
    echo "Failed to create PAM test configuration file. Exiting."
    exit 1
fi

echo "PAM test configuration created successfully at $PAM_CONF_PATH."
echo "------------------------------------------------------------"
echo "Testing authentication for user: $TEST_USER"
echo "We are running pamtester via sudo so the module can access /etc/shadow."
echo "You can authenticate using:"
echo "  - Swiping your registered fingerprint (if fprintd is configured)."
echo "  - OR typing your system password."
echo "------------------------------------------------------------"

# Run pamtester
sudo pamtester "$SERVICE_NAME" "$TEST_USER" authenticate

# Cleanup
echo "------------------------------------------------------------"
echo "Cleaning up test configuration..."
sudo rm -f "$PAM_CONF_PATH"
echo "Cleanup complete."
