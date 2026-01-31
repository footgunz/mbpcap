package decoder

import (
	"bytes"
	"testing"
)

// Reference data: slave 2, read holding register 177, response value 700.
// Request:  02 03 00 B1 00 01 D4 1E  (8 bytes, func 0x03)
// Response: 02 03 02 02 BC FC 95     (7 bytes, func 0x03 response with byte count 2)
var (
	reqFrame  = []byte{0x02, 0x03, 0x00, 0xB1, 0x00, 0x01, 0xD4, 0x1E}
	respFrame = []byte{0x02, 0x03, 0x02, 0x02, 0xBC, 0xFC, 0x95}
)

func TestFrameLen(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"func 0x01 (read coils)", []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0}, 8},
		{"func 0x02 (read discrete)", []byte{0x01, 0x02, 0, 0, 0, 0, 0, 0}, 8},
		{"func 0x03 (read holding)", reqFrame, 8},
		{"func 0x04 (read input)", []byte{0x01, 0x04, 0, 0, 0, 0, 0, 0}, 8},
		{"func 0x05 (write single coil)", []byte{0x01, 0x05, 0, 0, 0, 0, 0, 0}, 8},
		{"func 0x06 (write single reg)", []byte{0x01, 0x06, 0, 0, 0, 0, 0, 0}, 8},
		{"func 0x0F (write multiple coils)", []byte{0x01, 0x0F, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0}, 12},
		{"func 0x10 (write multiple regs)", []byte{0x01, 0x10, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0}, 13},
		{"exception 0x81", []byte{0x01, 0x81, 0x02, 0, 0}, 5},
		{"exception 0x83", []byte{0x01, 0x83, 0x02, 0, 0}, 5},
		{"exception 0x90", []byte{0x01, 0x90, 0x01, 0, 0}, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FrameLen(tt.data)
			if got != tt.want {
				t.Errorf("FrameLen() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFrameLenUnrecognized(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"func 0x00", []byte{0x01, 0x00, 0, 0, 0, 0}},
		{"func 0x07", []byte{0x01, 0x07, 0, 0, 0, 0}},
		{"func 0x7F", []byte{0x01, 0x7F, 0, 0, 0, 0}},
		{"func 0x91", []byte{0x01, 0x91, 0, 0, 0, 0}},
		{"func 0xFF", []byte{0x01, 0xFF, 0, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FrameLen(tt.data)
			if got != -1 {
				t.Errorf("FrameLen() = %d, want -1", got)
			}
		})
	}
}

func TestFrameLenTooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{0x01}},
		{"func 0x0F needs 7 bytes", []byte{0x01, 0x0F, 0, 0, 0, 0}},
		{"func 0x10 needs 7 bytes", []byte{0x01, 0x10, 0, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FrameLen(tt.data)
			if got != -1 {
				t.Errorf("FrameLen() = %d, want -1", got)
			}
		})
	}
}

func TestSplitFrames(t *testing.T) {
	merged := make([]byte, 0, len(reqFrame)+len(respFrame))
	merged = append(merged, reqFrame...)
	merged = append(merged, respFrame...)

	frames := SplitFrames(merged)
	if len(frames) != 2 {
		t.Fatalf("SplitFrames() returned %d frames, want 2", len(frames))
	}
	if !bytes.Equal(frames[0].Data, reqFrame) {
		t.Errorf("frame[0] = %x, want %x", frames[0].Data, reqFrame)
	}
	if frames[0].Dir != DirRequest {
		t.Errorf("frame[0].Dir = %d, want DirRequest (%d)", frames[0].Dir, DirRequest)
	}
	if !bytes.Equal(frames[1].Data, respFrame) {
		t.Errorf("frame[1] = %x, want %x", frames[1].Data, respFrame)
	}
	if frames[1].Dir != DirResponse {
		t.Errorf("frame[1].Dir = %d, want DirResponse (%d)", frames[1].Dir, DirResponse)
	}
}

func TestSplitFramesSingleFrame(t *testing.T) {
	frames := SplitFrames(reqFrame)
	if len(frames) != 1 {
		t.Fatalf("SplitFrames() returned %d frames, want 1", len(frames))
	}
	if !bytes.Equal(frames[0].Data, reqFrame) {
		t.Errorf("frame[0] = %x, want %x", frames[0].Data, reqFrame)
	}
	if frames[0].Dir != DirRequest {
		t.Errorf("frame[0].Dir = %d, want DirRequest (%d)", frames[0].Dir, DirRequest)
	}
}

func TestSplitFramesUnsplittable(t *testing.T) {
	garbage := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA}
	frames := SplitFrames(garbage)
	if len(frames) != 1 {
		t.Fatalf("SplitFrames() returned %d frames, want 1", len(frames))
	}
	if !bytes.Equal(frames[0].Data, garbage) {
		t.Errorf("frame[0] = %x, want %x", frames[0].Data, garbage)
	}
	if frames[0].Dir != DirUnknown {
		t.Errorf("frame[0].Dir = %d, want DirUnknown (%d)", frames[0].Dir, DirUnknown)
	}
}

func TestSplitFramesPartialExact(t *testing.T) {
	// Full request + full response → 2 frames, nil remainder
	merged := make([]byte, 0, len(reqFrame)+len(respFrame))
	merged = append(merged, reqFrame...)
	merged = append(merged, respFrame...)

	frames, remainder := SplitFramesPartial(merged)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if !bytes.Equal(frames[0].Data, reqFrame) {
		t.Errorf("frame[0] = %x, want %x", frames[0].Data, reqFrame)
	}
	if frames[0].Dir != DirRequest {
		t.Errorf("frame[0].Dir = %d, want DirRequest", frames[0].Dir)
	}
	if !bytes.Equal(frames[1].Data, respFrame) {
		t.Errorf("frame[1] = %x, want %x", frames[1].Data, respFrame)
	}
	if frames[1].Dir != DirResponse {
		t.Errorf("frame[1].Dir = %d, want DirResponse", frames[1].Dir)
	}
	if remainder != nil {
		t.Errorf("remainder = %x, want nil", remainder)
	}
}

func TestSplitFramesPartialTrailing(t *testing.T) {
	// Request + first 2 bytes of response → 1 request frame, 2-byte remainder
	partial := make([]byte, 0, len(reqFrame)+2)
	partial = append(partial, reqFrame...)
	partial = append(partial, respFrame[:2]...)

	frames, remainder := SplitFramesPartial(partial)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if !bytes.Equal(frames[0].Data, reqFrame) {
		t.Errorf("frame[0] = %x, want %x", frames[0].Data, reqFrame)
	}
	if frames[0].Dir != DirRequest {
		t.Errorf("frame[0].Dir = %d, want DirRequest", frames[0].Dir)
	}
	if !bytes.Equal(remainder, respFrame[:2]) {
		t.Errorf("remainder = %x, want %x", remainder, respFrame[:2])
	}
}

func TestSplitFramesPartialOnly(t *testing.T) {
	// Just a partial frame → 0 frames, entire input as remainder
	partial := respFrame[:3]
	frames, remainder := SplitFramesPartial(partial)
	if len(frames) != 0 {
		t.Fatalf("got %d frames, want 0", len(frames))
	}
	if !bytes.Equal(remainder, partial) {
		t.Errorf("remainder = %x, want %x", remainder, partial)
	}
}

func TestSplitFramesPartialReassembly(t *testing.T) {
	// Simulate remainder from previous cycle + rest of frame
	// Split response at byte 2: first 2 bytes are "remainder", rest arrives next
	remainderBytes := respFrame[:2]
	nextBuf := respFrame[2:]
	combined := make([]byte, 0, len(remainderBytes)+len(nextBuf))
	combined = append(combined, remainderBytes...)
	combined = append(combined, nextBuf...)

	frames, remainder := SplitFramesPartial(combined)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if !bytes.Equal(frames[0].Data, respFrame) {
		t.Errorf("frame[0] = %x, want %x", frames[0].Data, respFrame)
	}
	if frames[0].Dir != DirResponse {
		t.Errorf("frame[0].Dir = %d, want DirResponse", frames[0].Dir)
	}
	if remainder != nil {
		t.Errorf("remainder = %x, want nil", remainder)
	}
}

func TestSplitFramesPartialEmpty(t *testing.T) {
	frames, remainder := SplitFramesPartial([]byte{})
	if len(frames) != 0 {
		t.Fatalf("got %d frames, want 0", len(frames))
	}
	if remainder != nil {
		t.Errorf("remainder = %x, want nil", remainder)
	}
}

func TestSplitFramesPartialValidThenGarbage(t *testing.T) {
	// Valid request followed by unrecognized bytes → 1 frame, garbage as remainder
	garbage := []byte{0xFF, 0xFE}
	input := make([]byte, 0, len(reqFrame)+len(garbage))
	input = append(input, reqFrame...)
	input = append(input, garbage...)

	frames, remainder := SplitFramesPartial(input)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if !bytes.Equal(frames[0].Data, reqFrame) {
		t.Errorf("frame[0] = %x, want %x", frames[0].Data, reqFrame)
	}
	if frames[0].Dir != DirRequest {
		t.Errorf("frame[0].Dir = %d, want DirRequest", frames[0].Dir)
	}
	if !bytes.Equal(remainder, garbage) {
		t.Errorf("remainder = %x, want %x", remainder, garbage)
	}
}

func TestSplitFramesMultiple(t *testing.T) {
	// Three frames: request + response + another request
	triple := make([]byte, 0, len(reqFrame)+len(respFrame)+len(reqFrame))
	triple = append(triple, reqFrame...)
	triple = append(triple, respFrame...)
	triple = append(triple, reqFrame...)

	frames := SplitFrames(triple)
	if len(frames) != 3 {
		t.Fatalf("SplitFrames() returned %d frames, want 3", len(frames))
	}
	if !bytes.Equal(frames[0].Data, reqFrame) {
		t.Errorf("frame[0] = %x, want %x", frames[0].Data, reqFrame)
	}
	if frames[0].Dir != DirRequest {
		t.Errorf("frame[0].Dir = %d, want DirRequest (%d)", frames[0].Dir, DirRequest)
	}
	if !bytes.Equal(frames[1].Data, respFrame) {
		t.Errorf("frame[1] = %x, want %x", frames[1].Data, respFrame)
	}
	if frames[1].Dir != DirResponse {
		t.Errorf("frame[1].Dir = %d, want DirResponse (%d)", frames[1].Dir, DirResponse)
	}
	if !bytes.Equal(frames[2].Data, reqFrame) {
		t.Errorf("frame[2] = %x, want %x", frames[2].Data, reqFrame)
	}
	if frames[2].Dir != DirRequest {
		t.Errorf("frame[2].Dir = %d, want DirRequest (%d)", frames[2].Dir, DirRequest)
	}
}
