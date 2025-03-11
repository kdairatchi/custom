#!/usr/bin/env bash
# Endpointer - A script to capture screenshots for endpoints and launch the gowitness report server
# Author: Your Name
# Date: $(date +%Y-%m-%d)
#
# Description:
#   - Reads a user-supplied file containing endpoints (one URL per line).
#   - Uses gowitness to scan those endpoints and capture full-page screenshots.
#   - Launches the gowitness report server to allow visual review.
#
# Usage:
#   ./endpointer.sh -f endpoints.txt [-d output_directory]
#
# Example:
#   ./endpointer.sh -f my_endpoints.txt -d screenshots

usage() {
    echo "Usage: $0 -f endpoints.txt [-d output_directory]"
    exit 1
}

# Default output directory if not provided
OUTPUT_DIR="endpointer_screenshots"

while getopts "f:d:" opt; do
  case $opt in
    f) ENDPOINT_FILE="$OPTARG" ;;
    d) OUTPUT_DIR="$OPTARG" ;;
    *) usage ;;
  esac
done

if [ -z "$ENDPOINT_FILE" ]; then
    usage
fi

if [ ! -f "$ENDPOINT_FILE" ]; then
    echo "Error: File '$ENDPOINT_FILE' does not exist."
    exit 1
fi

echo "Using endpoints file: $ENDPOINT_FILE"
echo "Output directory: $OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR" || { echo "Failed to create output directory"; exit 1; }

echo -e "\n${BOLD_WHITE}[+] Starting endpoint scan with gowitness...${NC}"
# Scan endpoints and capture full-page screenshots, writing JSON output as well
gowitness scan file -f "$ENDPOINT_FILE" -D "$OUTPUT_DIR" --screenshot-fullpage --write-jsonl
if [ $? -ne 0 ]; then
    echo "gowitness scan failed."
    exit 1
fi

echo -e "\n${BOLD_GREEN}[+] Launching gowitness report server...${NC}"
# Launch the gowitness report server for the output directory
gowitness report serve -D "$OUTPUT_DIR"