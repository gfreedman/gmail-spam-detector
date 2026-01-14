#!/bin/bash
# Setup script for spam detector test environment

echo "Setting up spam detector test environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install requirements
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "Setup complete! To run the tests:"
echo "  1. Activate the environment: source venv/bin/activate"
echo "  2. Run the test script: python test_spam_detector.py"
echo ""
echo "Optional arguments:"
echo "  --verbose       Show detailed keyword matches"
echo "  --threshold N   Set spam threshold (default: 60)"
echo ""
echo "Examples:"
echo "  python test_spam_detector.py"
echo "  python test_spam_detector.py --verbose"
echo "  python test_spam_detector.py --threshold 70"
