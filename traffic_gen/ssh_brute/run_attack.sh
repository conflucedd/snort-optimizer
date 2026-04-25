#!/bin/bash
# Script to run SSH brute force attack and check alerts

cd /home/c/snort-optimizer/traffic_gen

echo "Building attack program..."
cd ssh_brute
go build -o simple_attack simple_attack.go
cd ..

echo "Checking if Snort is running..."
if ! ps aux | grep snort | grep -v grep > /dev/null; then
    echo "Snort is not running. Starting Snort..."
    ./start_snort.sh > snort.log 2>&1 &
    echo "Waiting 25 seconds for Snort initialization..."
    sleep 25
else
    echo "Snort is already running."
fi

echo "Running attack..."
./ssh_brute/simple_attack

echo "Checking alerts..."
if [ -f alert_fast.txt ]; then
    echo "Alerts in alert_fast.txt:"
    grep -i "ssh brute" alert_fast.txt || echo "No SSH brute force alerts found."
else
    echo "No alert_fast.txt found."
fi

echo "Done."