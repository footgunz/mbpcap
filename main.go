package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.bug.st/serial"

	"mbpcap/pkg/decoder"
	"mbpcap/pkg/pcap"
)

var Version = "dev"

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

// charBits returns the total number of bits per character on the wire
// (start + data + optional parity + stop).
func charBits(databits, stopbitsN int, parity string) int {
	bits := 1 + databits // start + data
	if parity != "none" {
		bits++
	}
	bits += stopbitsN
	return bits
}

// defaultSilence returns 3.5 character times for the given serial settings.
func defaultSilence(baud, databits, stopbitsN int, parity string) time.Duration {
	bits := charBits(databits, stopbitsN, parity)
	charTime := float64(bits) / float64(baud)
	return time.Duration(3.5 * charTime * float64(time.Second))
}

// modbusSilence returns the wire time for a max-length Modbus RTU frame
// (256 bytes) plus a fixed 25ms margin for USB serial adapter jitter.
func modbusSilence(baud, databits, stopbitsN int, parity string) time.Duration {
	bits := charBits(databits, stopbitsN, parity)
	wireTime := float64(256*bits) / float64(baud)
	return time.Duration(wireTime*float64(time.Second)) + 25*time.Millisecond
}

// rtacHeader builds a 12-byte RTAC Serial header (big-endian) for the given
// timestamp and event type.
func rtacHeader(ts time.Time, eventType byte) []byte {
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(ts.Unix()))
	binary.BigEndian.PutUint32(hdr[4:8], uint32(ts.Nanosecond()/1000))
	hdr[8] = eventType
	return hdr
}

func main() {
	baud := flag.Int("baud", 115200, "baud rate")
	databits := flag.Int("databits", 8, "data bits (5-8)")
	parityStr := flag.String("parity", "none", "parity: none, odd, even, mark, space")
	stopbitsInt := flag.Int("stopbits", 1, "stop bits: 1 or 2")
	output := flag.String("o", "", "output PCAP file path (required)")
	silenceUs := flag.Float64("silence", 0, "silence threshold in microseconds (0 = auto: 3.5 character times)")
	bigEndian := flag.Bool("bigendian", false, "write PCAP in big-endian byte order")
	modbusMode := flag.Bool("modbus", false, "enable Modbus RTU frame splitting")
	verbose := flag.Bool("v", false, "verbose: show live capture status on stderr")
	pipeMode := flag.Bool("pipe", false, "create a named pipe (FIFO) for live Wireshark streaming (Unix only)")

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

	var f *os.File
	if *pipeMode {
		f, err = createPipe(*output)
		if err != nil {
			_ = port.Close()
			log.Fatalf("create pipe: %v", err)
		}
	} else {
		f, err = os.Create(*output)
		if err != nil {
			_ = port.Close()
			log.Fatalf("create output file: %v", err)
		}
	}

	var byteOrder binary.ByteOrder = binary.LittleEndian
	if *bigEndian {
		byteOrder = binary.BigEndian
	}

	dlt := pcap.DLTUser0
	if *modbusMode {
		dlt = pcap.DLTRTACSer
	}

	pw, err := pcap.NewWriter(f, byteOrder, dlt)
	if err != nil {
		_ = f.Close()
		_ = port.Close()
		if *pipeMode {
			removePipe(*output)
		}
		log.Fatalf("write pcap header: %v", err)
	}
	defer func() { _ = f.Close() }()
	defer func() { _ = port.Close() }()
	if *pipeMode {
		defer removePipe(*output)
	}

	var silenceThreshold time.Duration
	switch {
	case *silenceUs > 0:
		silenceThreshold = time.Duration(*silenceUs * float64(time.Microsecond))
	case *modbusMode:
		silenceThreshold = modbusSilence(*baud, *databits, *stopbitsInt, *parityStr)
	default:
		silenceThreshold = defaultSilence(*baud, *databits, *stopbitsInt, *parityStr)
	}

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
	var pipeBroken bool
	silenceTimer := time.NewTimer(0)
	if !silenceTimer.Stop() {
		<-silenceTimer.C
	}

	packetCount := 0
	txCount := 0
	rxCount := 0
	unknownCount := 0
	var prevExtra []byte
	var prevExtraTime time.Time
	var lastStatus time.Time

	flush := func() {
		if len(packetBuf) == 0 {
			return
		}
		if *modbusMode {
			extra := prevExtra
			extraTime := prevExtraTime
			prevExtra = nil
			prevExtraTime = time.Time{}

			// Expire stale remainder: if the gap between the previous
			// remainder and this buffer exceeds the silence threshold,
			// the remainder is too old to belong to the current frame.
			if extra != nil && firstByteTime.Sub(extraTime) > silenceThreshold {
				if *verbose {
					log.Printf("expiring %d-byte remainder (age %s > silence %s)",
						len(extra), firstByteTime.Sub(extraTime), silenceThreshold)
				}
				extra = nil
			}

			baseTime := firstByteTime
			bitsPerChar := charBits(*databits, *stopbitsInt, *parityStr)

			// Try parsing the new buffer on its own first
			frames, remainder := decoder.SplitFramesPartial(packetBuf)

			if len(frames) == 0 && extra != nil {
				// New buffer didn't parse alone; try with previous remainder prepended
				combined := make([]byte, 0, len(extra)+len(packetBuf))
				combined = append(combined, extra...)
				combined = append(combined, packetBuf...)
				frames, remainder = decoder.SplitFramesPartial(combined)
				baseTime = extraTime
			} else if extra != nil && *verbose {
				log.Printf("discarding %d-byte remainder from previous cycle", len(extra))
			}

			if len(frames) > 0 {
				prevExtra = remainder
				if remainder != nil {
					parsedBytes := 0
					for _, f := range frames {
						parsedBytes += len(f.Data)
					}
					prevExtraTime = baseTime.Add(
						time.Duration(float64(parsedBytes*bitsPerChar) / float64(*baud) * float64(time.Second)),
					)
				}
				for i, frame := range frames {
					ts := baseTime
					if i > 0 {
						bytesSoFar := 0
						for j := range i {
							bytesSoFar += len(frames[j].Data)
						}
						wireTime := time.Duration(float64(bytesSoFar*bitsPerChar) / float64(*baud) * float64(time.Second))
						ts = baseTime.Add(wireTime)
					}
					payload := append(rtacHeader(ts, byte(frame.Dir)), frame.Data...)
					if err := pw.WritePacket(ts, payload); err != nil {
						if errors.Is(err, syscall.EPIPE) {
							pipeBroken = true
							return
						}
						log.Printf("write packet: %v", err)
					}
					packetCount++
					switch frame.Dir {
					case decoder.DirRequest:
						txCount++
					case decoder.DirResponse:
						rxCount++
					case decoder.DirUnknown:
						unknownCount++
					}
				}
			} else {
				// Nothing parsed — write as DirUnknown, including any stale remainder
				fallback := packetBuf
				fallbackTime := firstByteTime
				if extra != nil {
					fallback = make([]byte, 0, len(extra)+len(packetBuf))
					fallback = append(fallback, extra...)
					fallback = append(fallback, packetBuf...)
					fallbackTime = extraTime
				}
				payload := append(rtacHeader(fallbackTime, byte(decoder.DirUnknown)), fallback...)
				if err := pw.WritePacket(fallbackTime, payload); err != nil {
					if errors.Is(err, syscall.EPIPE) {
						pipeBroken = true
						return
					}
					log.Printf("write packet: %v", err)
				}
				packetCount++
				unknownCount++
			}
		} else {
			if err := pw.WritePacket(firstByteTime, packetBuf); err != nil {
				if errors.Is(err, syscall.EPIPE) {
					pipeBroken = true
					packetBuf = nil
					return
				}
				log.Printf("write packet: %v", err)
			}
			packetCount++
		}
		packetBuf = nil
	}

	modeStr := ""
	if *modbusMode {
		modeStr = " (modbus splitting)"
	}
	log.Printf("capturing on %s (%d baud) → %s (silence threshold: %s)%s",
		portPath, *baud, *output, silenceThreshold, modeStr)

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
			if pipeBroken {
				log.Printf("pipe closed by reader")
				log.Printf("captured %d packets", packetCount)
				return
			}
			if *verbose && time.Since(lastStatus) >= time.Second {
				if *modbusMode {
					fmt.Fprintf(os.Stderr, "\rpackets: %d (TX: %d  RX: %d  ?: %d)          ", packetCount, txCount, rxCount, unknownCount)
				} else {
					fmt.Fprintf(os.Stderr, "\rpackets: %d          ", packetCount)
				}
				lastStatus = time.Now()
			}

		case <-sigChan:
			flush()
			if *verbose {
				fmt.Fprintln(os.Stderr)
			}
			log.Printf("captured %d packets", packetCount)
			return

		case err := <-errChan:
			flush()
			if *verbose {
				fmt.Fprintln(os.Stderr)
			}
			log.Printf("serial read error: %v", err)
			log.Printf("captured %d packets", packetCount)
			return
		}
	}
}
