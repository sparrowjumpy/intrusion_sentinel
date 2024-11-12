#!/bin/bash

# Pull latest changes from GitHub
git pull origin main

# Add, commit, and push local changes
git add .
git commit -m "Auto-sync changes"
git push origin main
