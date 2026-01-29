package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestGlobalHeader(t *testing.T) {
	var buf bytes.Buffer
	_, err := NewWriter(&buf)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	b := buf.Bytes()
	if len(b) != 24 {
		t.Fatalf("global header length = %d, want 24", len(b))
	}

	magic := binary.LittleEndian.Uint32(b[0:4])
	if magic != 0xa1b2c3d4 {
		t.Errorf("magic = 0x%08x, want 0xa1b2c3d4", magic)
	}

	major := binary.LittleEndian.Uint16(b[4:6])
	if major != 2 {
		t.Errorf("version major = %d, want 2", major)
	}

	minor := binary.LittleEndian.Uint16(b[6:8])
	if minor != 4 {
		t.Errorf("version minor = %d, want 4", minor)
	}

	thiszone := int32(binary.LittleEndian.Uint32(b[8:12]))
	if thiszone != 0 {
		t.Errorf("thiszone = %d, want 0", thiszone)
	}

	sigfigs := binary.LittleEndian.Uint32(b[12:16])
	if sigfigs != 0 {
		t.Errorf("sigfigs = %d, want 0", sigfigs)
	}

	snaplen := binary.LittleEndian.Uint32(b[16:20])
	if snaplen != 65535 {
		t.Errorf("snaplen = %d, want 65535", snaplen)
	}

	linkType := binary.LittleEndian.Uint32(b[20:24])
	if linkType != 147 {
		t.Errorf("link type = %d, want 147", linkType)
	}
}

func TestWritePacket(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	buf.Reset() // discard global header for this test

	ts := time.Date(2025, 1, 15, 10, 30, 45, 123456789, time.UTC)
	data := []byte{0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD}

	if err := w.WritePacket(ts, data); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	b := buf.Bytes()
	if len(b) != 16+len(data) {
		t.Fatalf("packet length = %d, want %d", len(b), 16+len(data))
	}

	tsSec := binary.LittleEndian.Uint32(b[0:4])
	if tsSec != uint32(ts.Unix()) {
		t.Errorf("ts_sec = %d, want %d", tsSec, ts.Unix())
	}

	tsUsec := binary.LittleEndian.Uint32(b[4:8])
	wantUsec := uint32(123456789 / 1000)
	if tsUsec != wantUsec {
		t.Errorf("ts_usec = %d, want %d", tsUsec, wantUsec)
	}

	capLen := binary.LittleEndian.Uint32(b[8:12])
	if capLen != uint32(len(data)) {
		t.Errorf("cap_len = %d, want %d", capLen, len(data))
	}

	origLen := binary.LittleEndian.Uint32(b[12:16])
	if origLen != uint32(len(data)) {
		t.Errorf("orig_len = %d, want %d", origLen, len(data))
	}

	if !bytes.Equal(b[16:], data) {
		t.Errorf("packet data = %x, want %x", b[16:], data)
	}
}

func TestMultiplePackets(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ts1 := time.Date(2025, 1, 15, 10, 30, 45, 0, time.UTC)
	data1 := []byte{0x01, 0x02, 0x03}

	ts2 := time.Date(2025, 1, 15, 10, 30, 46, 500000000, time.UTC)
	data2 := []byte{0x04, 0x05}

	if err := w.WritePacket(ts1, data1); err != nil {
		t.Fatalf("WritePacket 1: %v", err)
	}
	if err := w.WritePacket(ts2, data2); err != nil {
		t.Fatalf("WritePacket 2: %v", err)
	}

	b := buf.Bytes()
	expectedLen := 24 + (16 + len(data1)) + (16 + len(data2))
	if len(b) != expectedLen {
		t.Fatalf("total length = %d, want %d", len(b), expectedLen)
	}

	// Verify second packet starts at correct offset
	pkt2Offset := 24 + 16 + len(data1)
	tsSec2 := binary.LittleEndian.Uint32(b[pkt2Offset : pkt2Offset+4])
	if tsSec2 != uint32(ts2.Unix()) {
		t.Errorf("packet 2 ts_sec = %d, want %d", tsSec2, ts2.Unix())
	}

	tsUsec2 := binary.LittleEndian.Uint32(b[pkt2Offset+4 : pkt2Offset+8])
	if tsUsec2 != 500000 {
		t.Errorf("packet 2 ts_usec = %d, want 500000", tsUsec2)
	}

	capLen2 := binary.LittleEndian.Uint32(b[pkt2Offset+8 : pkt2Offset+12])
	if capLen2 != uint32(len(data2)) {
		t.Errorf("packet 2 cap_len = %d, want %d", capLen2, len(data2))
	}

	if !bytes.Equal(b[pkt2Offset+16:pkt2Offset+16+len(data2)], data2) {
		t.Errorf("packet 2 data mismatch")
	}
}
