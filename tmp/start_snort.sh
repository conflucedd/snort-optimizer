#! /bin/bash
rm alert_json.txt alert_fast.txt
#$SNORT_DIR/snort --daq-dir $DAQ_DIR -c config/snort.lua -i enp11s0 --daq afpacket

$SNORT_DIR/snort --daq-dir $DAQ_DIR -c config/snort.lua -r ../data/Wednesday.pcap