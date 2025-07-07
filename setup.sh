#!/bin/bash

# Computer Security Project Setup Script
# This script sets up the development environment for the RSA Key Management System

echo "🔐 Computer Security Project - Setup Script"
echo "============================================"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or later."
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 is not installed. Please install pip3."
    exit 1
fi

echo "✅ pip3 found"

# Install system dependencies for Ubuntu/Debian
if command -v apt &> /dev/null; then
    echo "🔧 Installing system dependencies (tkinter)..."
    sudo apt update
    sudo apt install -y python3-tk
    echo "✅ System dependencies installed"
fi

# Create virtual environment
echo "🔧 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "🔧 Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "🔧 Installing Python dependencies..."
pip install -r requirements-minimal.txt

echo ""
echo "🎉 Setup completed successfully!"
echo ""
echo "To run the application:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Run the application: python3 main.py"
echo ""
echo "To run tests:"
echo "python3 test_rsa.py"
echo ""
echo "To deactivate virtual environment:"
echo "deactivate"
