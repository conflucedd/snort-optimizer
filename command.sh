go run . \
  --swd /home/c/snort-optimizer/config/ \
  --config /home/c/snort-optimizer/config/snort.lua \
  --need-output \
  --pcap /home/c/snort-optimizer

ip netns add test
ip link set enp12s0u5u3c2 netns test
ip netns exec test ip addr add 192.168.1.4/24 dev enp12s0u5u3c2
ip netns exec test ip link set enp12s0u5u3c2 up
ip netns exec test ip route add default via 192.168.1.100

ip netns exec test sysctl -w net.ipv4.ping_group_range="0 2147483647"

$SNORT_DIR/snort --daq-dir $DAQ_DIR -c config/snort.lua -i enp11s0 --daq afpacket
$SNORT_DIR/snort --daq-dir $DAQ_DIR -c config/snort.lua -r ../data/new_csv/malicious.pcap
