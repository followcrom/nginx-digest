#!/bin/bash

# Absolute paths
VENV_PATH="/var/www/digest/dig_venv"
SCRIPT_PATH="/var/www/digest/nginx_digest.py"
LOG_FILE="/var/www/digest/nginx_digest.log"

# Change to project directory
cd /var/www/digest || {
    echo "$(date) - Error: Failed to change directory to /var/www/digest" >> "$LOG_FILE"
    exit 1
}

# Activate virtual environment
source "$VENV_PATH/bin/activate"

# Run Python script
python_output=$(python "$SCRIPT_PATH" 2>&1)
exit_code=$?

# Deactivate virtual environment
deactivate

# Log script output
echo "$python_output" >> "$LOG_FILE"

# Check if the script failed
if [ $exit_code -ne 0 ]; then
    echo "Error: Python script failed with exit code $exit_code" >> "$LOG_FILE"

    # Compose email body
    email_body="$(date) - Nginx Analysis Error
Exit Code: $exit_code

Output:
$python_output"

    # Send email notification
    echo "$email_body" | mail -s "Nginx Analysis Error" followcrom@gmail.com
    # Log that the email was sent
    echo "$(date) - Notification email sent regarding script failure." >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"

    exit $exit_code
fi

# Success
echo -e "Cron job complete!\n" >> "$LOG_FILE"
