#!/bin/bash

# --- Configuration ---
# URL for the raw regexes.yaml file
FILE_URL="https://raw.githubusercontent.com/ua-parser/uap-core/master/regexes.yaml"

# Default destination file name
DEFAULT_FILE="regexes.yaml"

# --- Argument Check ---
# Check if a command-line argument ($1) was provided
if [ -z "$1" ]; then
    # If $1 is empty (no argument), use the default file name
    DEST_FILE="$DEFAULT_FILE"
    echo "No path argument provided. Defaulting to: $DEST_FILE"
else
    # If $1 is provided, use it as the destination file name
    DEST_FILE="$1"
    echo "Using provided path argument: $DEST_FILE"
fi

# --- Download Logic ---
echo "Downloading $FILE_URL..."

# Use curl to download the file. 
# -L: Follow redirects
# -o: Write output to the specified file
curl -L "$FILE_URL" -o "$DEST_FILE"

# --- Status Check ---
if [ $? -eq 0 ]; then
    echo "✅ Successfully downloaded file to: $DEST_FILE"
else
    echo "❌ Error: Download failed."
fi