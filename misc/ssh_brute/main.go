package main

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	target := "192.168.1.3:22"
	attempts := 30
	timeout := 5 * time.Second

	// Use a fake username and password that will fail
	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.Password("wrongpassword"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	for i := 1; i <= attempts; i++ {
		fmt.Printf("Attempt %d/%d... ", i, attempts)
		start := time.Now()

		conn, err := net.DialTimeout("tcp", target, timeout)
		if err != nil {
			fmt.Printf("TCP dial failed: %v\n", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		sshConn, _, _, err := ssh.NewClientConn(conn, target, config)
		if err != nil {
			fmt.Printf("SSH handshake failed: %v\n", err)
			conn.Close()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Close the connection
		sshConn.Close()
		fmt.Printf("SSH handshake completed (auth failed), duration: %v\n", time.Since(start))
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("Attack completed")
}
