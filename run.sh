#!/bin/bash

# Run script for SCX Lottery Scheduler

set -e  # Exit on any error

echo "Starting SCX Lottery Scheduler..."

# Check if binary exists
if [ ! -f "./scx_lottery" ]; then
    echo "Error: scx_lottery binary not found. Run ./build.sh first."
    exit 1
fi

# Check if running as root (required for sched_ext)
if [ "$EUID" -ne 0 ]; then
    echo "Error: This scheduler must be run as root (sudo)."
    echo "Usage: sudo ./run.sh"
    exit 1
fi

# Run the scheduler
echo "Lottery scheduler starting... Press Ctrl+C to stop."
./scx_lottery

echo "Scheduler stopped."