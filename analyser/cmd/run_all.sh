set -e

echo "开始执行周二任务..."
./cmd --pcap1 ../../data/Tuesday.pcap --db1 ../../data/Tuesday.db --pcap2 ../../data/Monday.pcap --config ../../config/snort.lua --raw-snort-sqlite snort.sqlite --workdir ./analyser_result/Tuesday_result --disable-strategy safe_inactive_systemd_services

echo "开始执行周三任务..."
./cmd --pcap1 ../../data/Wednesday.pcap --db1 ../../data/Wednesday.db --pcap2 ../../data/Monday.pcap --config ../../config/snort.lua --raw-snort-sqlite snort.sqlite --workdir ./analyser_result/Wednesday_result --disable-strategy safe_inactive_systemd_services

echo "开始执行周四任务..."
./cmd --pcap1 ../../data/Thursday.pcap --db1 ../../data/Thursday.db --pcap2 ../../data/Monday.pcap --config ../../config/snort.lua --raw-snort-sqlite snort.sqlite --workdir ./analyser_result/Thursday_result --disable-strategy safe_inactive_systemd_services

echo "开始执行周五任务..."
./cmd --pcap1 ../../data/Friday.pcap --db1 ../../data/Friday.db --pcap2 ../../data/Monday.pcap --config ../../config/snort.lua --raw-snort-sqlite snort.sqlite --workdir ./analyser_result/Friday_result --disable-strategy safe_inactive_systemd_services

echo "所有任务执行完毕。"
