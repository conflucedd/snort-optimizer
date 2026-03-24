package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// snort --daq-dir snort/libdaq/build/lib/daq -r traffic/Friday-WorkingHours.pcap -c config/snort.lua

func main() {
	// cmd := exec.Command(
	// 	"stdbuf", "-oL", "-eL",
	// 	//"snort",
	// 	"snort/install/bin/snort",
	// 	"--daq-dir", "snort/libdaq/build/lib/daq",
	// 	"-c", "config/snort.lua",
	// 	"-r", "data/CIC-IDS-2017/Friday-WorkingHours.pcap",
	// )
	cmd := exec.Command(
		"snort/install/bin/snort",
		"--daq-dir", "snort/libdaq/build/lib/daq",
		"-c", "config/snort.lua",
		"-i", "enp11s0",
	)

	// 创建输出文件
	outFile, err := os.Create("snort_output.txt")
	if err != nil {
		log.Fatal("无法创建输出文件:", err)
	}
	defer outFile.Close()

	// 创建同时写入终端和文件的writer
	multiWriter := io.MultiWriter(os.Stdout, outFile)

	cmd.Stdout = multiWriter
	cmd.Stderr = multiWriter

	cmd.Start()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		if cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
	}()

	cmd.Wait()
}
