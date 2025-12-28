# HaleDistrict - First Script
# Purpose: Create folders for automation and logging

New-Item -ItemType Directory -Path "C:\HaleDistrict\Scripts" -Force
New-Item -ItemType Directory -Path "C:\HaleDistrict\Logs" -Force

Write-Output "Folders created successfully."