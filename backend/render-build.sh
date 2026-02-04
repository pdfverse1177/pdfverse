#!/usr/bin/env bash
# exit on error
set -o errexit

# Install system dependencies for Pillow
apt-get update
apt-get install -y \
    libjpeg-dev \
    zlib1g-dev \
    libfreetype6-dev \
    liblcms2-dev \
    libopenjp2-7-dev \
    libtiff-dev \
    tk-dev \
    tcl-dev

# Upgrade pip
pip install --upgrade pip setuptools wheel

# Install Python packages
pip install -r requirements.txt
