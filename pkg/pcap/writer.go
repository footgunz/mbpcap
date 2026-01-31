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

	DLTUser0   uint32 = 147
	DLTRTACSer uint32 = 250
)

// Writer writes packets in libpcap format.
type Writer struct {
	w     io.Writer
	order binary.ByteOrder
}

// NewWriter creates a Writer and writes the 24-byte pcap global header.
// The byte order determines the endianness of all header fields in the file.
// The dlt parameter sets the link-layer header type (e.g. DLTUser0, DLTRTACSer).
func NewWriter(w io.Writer, order binary.ByteOrder, dlt uint32) (*Writer, error) {
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
		LinkType:     dlt,
	}
	if err := binary.Write(w, order, &hdr); err != nil {
		return nil, err
	}
	return &Writer{w: w, order: order}, nil
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
	if err := binary.Write(pw.w, pw.order, &hdr); err != nil {
		return err
	}
	_, err := pw.w.Write(data)
	return err
}
