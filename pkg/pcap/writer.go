package pcap

import (
	"encoding/binary"
	"io"
	"time"
)

const (
	magicNumber  uint32 = 0xa1b2c3d4
	versionMajor uint16 = 2
	versionMinor uint16 = 4
	snapLen      uint32 = 65535
	dltUser0     uint32 = 147
)

// Writer writes packets in libpcap format.
type Writer struct {
	w io.Writer
}

// NewWriter creates a Writer and writes the 24-byte pcap global header.
func NewWriter(w io.Writer) (*Writer, error) {
	hdr := struct {
		Magic        uint32
		VersionMajor uint16
		VersionMinor uint16
		ThisZone     int32
		SigFigs      uint32
		SnapLen      uint32
		LinkType     uint32
	}{
		Magic:        magicNumber,
		VersionMajor: versionMajor,
		VersionMinor: versionMinor,
		SnapLen:      snapLen,
		LinkType:     dltUser0,
	}
	if err := binary.Write(w, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}
	return &Writer{w: w}, nil
}

// WritePacket writes a single packet with its timestamp and raw data.
func (pw *Writer) WritePacket(ts time.Time, data []byte) error {
	length := uint32(len(data))
	hdr := struct {
		TsSec   uint32
		TsUsec  uint32
		CapLen  uint32
		OrigLen uint32
	}{
		TsSec:   uint32(ts.Unix()),
		TsUsec:  uint32(ts.Nanosecond() / 1000),
		CapLen:  length,
		OrigLen: length,
	}
	if err := binary.Write(pw.w, binary.LittleEndian, &hdr); err != nil {
		return err
	}
	_, err := pw.w.Write(data)
	return err
}
