package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	attempts := 10
	timeout := 2 * time.Second

	// Bind to secondary IP
	localAddr, _ := net.ResolveTCPAddr("tcp", "192.168.1.4:0")

	for i := 1; i <= attempts; i++ {
		fmt.Printf("Attempt %d/%d... ", i, attempts)
		conn, err := net.DialTCP("tcp", localAddr, &net.TCPAddr{IP: net.ParseIP("192.168.1.3"), Port: 22})
		if err != nil {
			fmt.Printf("Connection failed: %v\n", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}

		// Send SSH protocol identification string
		sshHeader := "SSH-2.0-GoClient\r\n"
		_, err = conn.Write([]byte(sshHeader))
		if err != nil {
			fmt.Printf("Write failed: %v\n", err)
			conn.Close()
			time.Sleep(50 * time.Millisecond)
			continue
		}

		// Read a small response
		buf := make([]byte, 256)
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, _ := conn.Read(buf)
		if n > 0 {
			fmt.Printf("Received: %s", string(buf[:n]))
		}

		conn.Close()
		fmt.Println("Sent SSH header and closed connection")
		time.Sleep(50 * time.Millisecond)
	}

	fmt.Println("Attack completed")
}
