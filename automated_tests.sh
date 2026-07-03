#!/bin/bash
# automated_tests.sh - Automated integration tests for pam_password_fingerprint

# Check if pamtester is installed
if ! command -v pamtester &> /dev/null; then
    echo "Error: 'pamtester' is not installed. Please install it."
    exit 1
fi

SERVICE_NAME="pam_test_password_fingerprint_auto"
PAM_CONF_PATH="/etc/pam.d/$SERVICE_NAME"
PAM_MODULE_PATH="$(pwd)/target/release/libpam_password_fingerprint.so"

if [ ! -f "$PAM_MODULE_PATH" ]; then
    echo "Error: target/release/libpam_password_fingerprint.so not found. Please build it first with 'make'."
    exit 1
fi

TEST_USER=$(logname 2>/dev/null || echo $USER)

cleanup() {
    sudo rm -f "$PAM_CONF_PATH"
}
trap cleanup EXIT

echo "=== Running Automated PAM Module Tests ==="

# Test Case 1: Validate tries=2 configuration limits prompting to exactly 2 attempts
echo "[Test 1] Testing tries=2 limit..."
sudo bash -c "cat > $PAM_CONF_PATH" <<EOF
auth required $PAM_MODULE_PATH tries=2
account required pam_permit.so
EOF

# Pipe 5 empty inputs. If tries=2 works, the prompt should terminate after 2 attempts.
# We capture stderr to count the number of "Password incorrect" messages.
output=$(echo -e "\n\n\n\n\n" | sudo pamtester "$SERVICE_NAME" "$TEST_USER" authenticate 2>&1)
incorrect_count=$(echo "$output" | grep -c "Password incorrect")

if [ "$incorrect_count" -eq 2 ]; then
    echo "  -> SUCCESS: Got exactly 2 password failure messages."
else
    echo "  -> FAILURE: Expected 2 failure messages, got $incorrect_count. Output: $output"
    exit 1
fi

# Test Case 2: Validate tries=4 configuration limits prompting to exactly 4 attempts
echo "[Test 2] Testing tries=4 limit..."
sudo bash -c "cat > $PAM_CONF_PATH" <<EOF
auth required $PAM_MODULE_PATH tries=4
account required pam_permit.so
EOF

output=$(echo -e "\n\n\n\n\n" | sudo pamtester "$SERVICE_NAME" "$TEST_USER" authenticate 2>&1)
incorrect_count=$(echo "$output" | grep -c "Password incorrect")

if [ "$incorrect_count" -eq 4 ]; then
    echo "  -> SUCCESS: Got exactly 4 password failure messages."
else
    echo "  -> FAILURE: Expected 4 failure messages, got $incorrect_count. Output: $output"
    exit 1
fi

# Test Case 3: Validate tries=1 limit (immediate failure without printing "attempt X/Y")
echo "[Test 3] Testing tries=1 limit (no warning details)..."
sudo bash -c "cat > $PAM_CONF_PATH" <<EOF
auth required $PAM_MODULE_PATH tries=1
account required pam_permit.so
EOF

output=$(echo -e "\n\n" | sudo pamtester "$SERVICE_NAME" "$TEST_USER" authenticate 2>&1)
incorrect_count=$(echo "$output" | grep -c "Password incorrect")

if [ "$incorrect_count" -eq 0 ]; then
    echo "  -> SUCCESS: No 'Password incorrect' attempts shown for tries=1."
else
    echo "  -> FAILURE: Expected 0 attempt warnings, got $incorrect_count. Output: $output"
    exit 1
fi

# Test Case 4: Validate password_tries override (takes precedence over tries)
echo "[Test 4] Testing password_tries override..."
sudo bash -c "cat > $PAM_CONF_PATH" <<EOF
auth required $PAM_MODULE_PATH tries=5 password_tries=3
account required pam_permit.so
EOF

output=$(echo -e "\n\n\n\n\n" | sudo pamtester "$SERVICE_NAME" "$TEST_USER" authenticate 2>&1)
incorrect_count=$(echo "$output" | grep -c "Password incorrect")

if [ "$incorrect_count" -eq 3 ]; then
    echo "  -> SUCCESS: Got exactly 3 password failure messages, overriding global tries=5."
else
    echo "  -> FAILURE: Expected 3 failure messages, got $incorrect_count. Output: $output"
    exit 1
fi

echo "=== All Automated Integration Tests Passed Successfully! ==="
