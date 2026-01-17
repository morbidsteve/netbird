// Package main provides a tool to capture and analyze FIPS-encrypted DTLS traffic.
//
// Usage:
//
//	# Start server mode (captures traffic on specified port)
//	go run main.go -mode server -port 51821 -pcap capture.pcap
//
//	# Start client mode (connects to server)
//	go run main.go -mode client -addr 127.0.0.1:51821
//
//	# Analyze captured pcap
//	tcpdump -r capture.pcap -X
//	wireshark capture.pcap
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
)

var (
	mode     = flag.String("mode", "server", "Mode: server or client")
	port     = flag.Int("port", 51821, "Port for DTLS server")
	addr     = flag.String("addr", "127.0.0.1:51821", "Address for client to connect to")
	pcapFile = flag.String("pcap", "", "Path to pcap file for capture (requires tcpdump)")
	psk      = flag.String("psk", "netbird-fips-test-key-123", "Pre-shared key for DTLS")
	duration = flag.Duration("duration", 30*time.Second, "Capture duration")
)

func main() {
	flag.Parse()

	// FIPS-approved cipher suite configuration
	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			return []byte(*psk), nil
		},
		PSKIdentityHint: []byte("netbird-fips-test"),
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
		},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	switch *mode {
	case "server":
		runServer(config)
	case "client":
		runClient(config)
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}

func runServer(config *dtls.Config) {
	// Start tcpdump if pcap file specified
	var tcpdumpCmd *exec.Cmd
	if *pcapFile != "" {
		tcpdumpCmd = startCapture(*port, *pcapFile)
		if tcpdumpCmd != nil {
			defer stopCapture(tcpdumpCmd)
		}
	}

	addr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: *port}

	log.Printf("Starting FIPS DTLS server on %s", addr)
	log.Printf("Cipher suite: TLS_PSK_WITH_AES_128_GCM_SHA256 (FIPS-approved)")
	log.Printf("PSK Identity: netbird-fips-test")

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		log.Fatalf("Failed to start DTLS listener: %v", err)
	}
	defer listener.Close()

	// Handle shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		listener.Close()
	}()

	log.Println("Waiting for connections...")

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	log.Printf("New connection from %s", conn.RemoteAddr())

	// Get DTLS connection state
	if dtlsConn, ok := conn.(*dtls.Conn); ok {
		state, _ := dtlsConn.ConnectionState()
		log.Printf("DTLS Connection State:")
		log.Printf("  Cipher Suite: %s", dtls.CipherSuiteName(state.CipherSuiteID))
	}

	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			return
		}

		log.Printf("Received %d bytes: %s", n, string(buf[:n]))

		// Echo back
		response := fmt.Sprintf("FIPS-ECHO: %s", buf[:n])
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Printf("Write error: %v", err)
			return
		}
	}
}

func runClient(config *dtls.Config) {
	log.Printf("Connecting to FIPS DTLS server at %s", *addr)
	log.Printf("Cipher suite: TLS_PSK_WITH_AES_128_GCM_SHA256 (FIPS-approved)")

	raddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatalf("Failed to resolve address: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dtls.Dial("udp", raddr, config)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Get connection state
	state, _ := conn.ConnectionState()
	log.Printf("Connected!")
	log.Printf("DTLS Connection State:")
	log.Printf("  Cipher Suite: %s", dtls.CipherSuiteName(state.CipherSuiteID))

	// Send test messages
	messages := []string{
		"Hello FIPS!",
		"Testing AES-128-GCM encryption",
		"This traffic is FIPS 140-3 compliant",
	}

	for _, msg := range messages {
		log.Printf("Sending: %s", msg)
		_, err := conn.Write([]byte(msg))
		if err != nil {
			log.Printf("Write error: %v", err)
			break
		}

		// Read response
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Read error: %v", err)
			break
		}
		log.Printf("Received: %s", string(buf[:n]))

		time.Sleep(500 * time.Millisecond)
	}

	_ = ctx // silence unused warning
	log.Println("Client finished")
}

func startCapture(port int, pcapFile string) *exec.Cmd {
	// Check if tcpdump is available
	if _, err := exec.LookPath("tcpdump"); err != nil {
		log.Printf("tcpdump not found, skipping capture. Install with: brew install tcpdump (macOS) or apt install tcpdump (Linux)")
		return nil
	}

	// Start tcpdump
	cmd := exec.Command("tcpdump",
		"-i", "lo0", // Use lo0 for macOS, lo for Linux
		"-w", pcapFile,
		"-s", "0", // Capture full packets
		fmt.Sprintf("udp port %d", port),
	)

	// Try lo for Linux if lo0 fails
	cmd.Stderr = os.Stderr
	err := cmd.Start()
	if err != nil {
		// Try Linux interface
		cmd = exec.Command("tcpdump",
			"-i", "lo",
			"-w", pcapFile,
			"-s", "0",
			fmt.Sprintf("udp port %d", port),
		)
		cmd.Stderr = os.Stderr
		err = cmd.Start()
		if err != nil {
			log.Printf("Failed to start tcpdump: %v", err)
			return nil
		}
	}

	log.Printf("Started packet capture to %s", pcapFile)
	time.Sleep(1 * time.Second) // Give tcpdump time to start
	return cmd
}

func stopCapture(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		log.Println("Stopping packet capture...")
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	}
}
