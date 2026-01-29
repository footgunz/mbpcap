package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.bug.st/serial"

	"mbpcap/pkg/pcap"
)

type readResult struct {
	data []byte
	ts   time.Time
}

func parseParity(s string) (serial.Parity, error) {
	switch s {
	case "none":
		return serial.NoParity, nil
	case "odd":
		return serial.OddParity, nil
	case "even":
		return serial.EvenParity, nil
	case "mark":
		return serial.MarkParity, nil
	case "space":
		return serial.SpaceParity, nil
	default:
		return serial.NoParity, fmt.Errorf("invalid parity %q: use none, odd, even, mark, or space", s)
	}
}

func parseStopBits(n int) (serial.StopBits, error) {
	switch n {
	case 1:
		return serial.OneStopBit, nil
	case 2:
		return serial.TwoStopBits, nil
	default:
		return serial.OneStopBit, fmt.Errorf("invalid stop bits %d: use 1 or 2", n)
	}
}

func main() {
	baud := flag.Int("baud", 115200, "baud rate")
	databits := flag.Int("databits", 8, "data bits (5-8)")
	parityStr := flag.String("parity", "none", "parity: none, odd, even, mark, space")
	stopbitsInt := flag.Int("stopbits", 1, "stop bits: 1 or 2")
	output := flag.String("o", "", "output PCAP file path (required)")
	silenceMs := flag.Int("silence", 20, "silence threshold in milliseconds")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mbpcap [flags] <serial-port>\n\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	portPath := flag.Arg(0)

	if *output == "" {
		fmt.Fprintln(os.Stderr, "error: -o (output file) is required")
		flag.Usage()
		os.Exit(1)
	}

	parity, err := parseParity(*parityStr)
	if err != nil {
		log.Fatal(err)
	}

	stopbits, err := parseStopBits(*stopbitsInt)
	if err != nil {
		log.Fatal(err)
	}

	port, err := serial.Open(portPath, &serial.Mode{
		BaudRate: *baud,
		DataBits: *databits,
		Parity:   parity,
		StopBits: stopbits,
	})
	if err != nil {
		log.Fatalf("open serial port: %v", err)
	}
	defer port.Close()

	f, err := os.Create(*output)
	if err != nil {
		log.Fatalf("create output file: %v", err)
	}
	defer f.Close()

	pw, err := pcap.NewWriter(f)
	if err != nil {
		log.Fatalf("write pcap header: %v", err)
	}

	silenceThreshold := time.Duration(*silenceMs) * time.Millisecond

	dataChan := make(chan readResult, 64)
	errChan := make(chan error, 1)

	// Reader goroutine
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := port.Read(buf)
			if err != nil {
				errChan <- err
				return
			}
			if n > 0 {
				ts := time.Now()
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				dataChan <- readResult{data: chunk, ts: ts}
			}
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var packetBuf []byte
	var firstByteTime time.Time
	silenceTimer := time.NewTimer(0)
	if !silenceTimer.Stop() {
		<-silenceTimer.C
	}

	packetCount := 0

	flush := func() {
		if len(packetBuf) == 0 {
			return
		}
		if err := pw.WritePacket(firstByteTime, packetBuf); err != nil {
			log.Printf("write packet: %v", err)
		}
		packetCount++
		packetBuf = nil
	}

	log.Printf("capturing on %s (%d baud) → %s (silence threshold: %dms)",
		portPath, *baud, *output, *silenceMs)

	for {
		select {
		case chunk := <-dataChan:
			if len(packetBuf) == 0 {
				firstByteTime = chunk.ts
			}
			packetBuf = append(packetBuf, chunk.data...)
			silenceTimer.Reset(silenceThreshold)

		case <-silenceTimer.C:
			flush()

		case <-sigChan:
			flush()
			log.Printf("captured %d packets", packetCount)
			return

		case err := <-errChan:
			flush()
			log.Printf("serial read error: %v", err)
			log.Printf("captured %d packets", packetCount)
			return
		}
	}
}
