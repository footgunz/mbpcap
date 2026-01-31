package decoder

// Direction classifies a Modbus RTU frame as a request or response.
// The values intentionally match the RTAC Serial event type byte.
type Direction uint8

const (
	DirUnknown  Direction = 0x00 // STATUS_CHANGE — can't classify
	DirRequest  Direction = 0x01 // DATA_TX_START
	DirResponse Direction = 0x02 // DATA_RX_START
)

// Frame is a decoded Modbus RTU frame with its classified direction.
type Frame struct {
	Data []byte
	Dir  Direction
}

type frameCandidate struct {
	length int
	dir    Direction
}

// frameCandidates returns the possible Modbus RTU frame lengths and their
// classified directions given bytes starting at a frame boundary. Function
// codes 0x01–0x04 are ambiguous (requests are fixed 8 bytes, responses are
// variable 5+data[2]), so both candidates are returned with the request first.
// Function codes 0x05/0x06 return DirUnknown because request and response are
// identical format. Returns nil if the data is too short or the function code
// is unrecognized.
func frameCandidates(data []byte) []frameCandidate {
	if len(data) < 2 {
		return nil
	}
	fc := data[1]

	switch {
	case fc >= 0x01 && fc <= 0x04:
		candidates := []frameCandidate{{8, DirRequest}}
		if len(data) >= 3 {
			respLen := 5 + int(data[2])
			if respLen != 8 {
				candidates = append(candidates, frameCandidate{respLen, DirResponse})
			}
		}
		return candidates
	case fc == 0x05 || fc == 0x06:
		return []frameCandidate{{8, DirUnknown}}
	case fc == 0x0F || fc == 0x10:
		if len(data) < 7 {
			return nil
		}
		return []frameCandidate{
			{9 + int(data[6]), DirRequest},
			{8, DirResponse},
		}
	case fc >= 0x81 && fc <= 0x90:
		return []frameCandidate{{5, DirResponse}}
	default:
		return nil
	}
}

// FrameLen returns the expected Modbus RTU frame length given bytes starting
// at a frame boundary. Returns -1 if the data is too short to determine the
// length or the function code is unrecognized. For ambiguous function codes
// (0x01–0x04), returns the request length (8).
func FrameLen(data []byte) int {
	candidates := frameCandidates(data)
	if len(candidates) == 0 {
		return -1
	}
	return candidates[0].length
}

// ValidCRC checks the Modbus CRC-16 of a frame.
// Stub: always returns true. Real CRC-16 (poly 0xA001, init 0xFFFF) to be added later.
func ValidCRC(_ []byte) bool {
	return true
}

// SplitFrames splits a byte slice containing concatenated Modbus RTU frames
// into individual frames with classified directions. If the frames don't
// consume the entire slice exactly, the original data is returned unsplit
// with DirUnknown.
//
// For ambiguous function codes (0x01–0x04, which can be either fixed-length
// requests or variable-length responses), both interpretations are tried.
func SplitFrames(data []byte) []Frame {
	result := splitFrom(data, 0, nil)
	if result == nil {
		return []Frame{{Data: data, Dir: DirUnknown}}
	}
	return result
}

// SplitFramesPartial greedily parses as many complete Modbus RTU frames as
// possible from the front of data and returns them along with any unparsed
// remainder bytes. If all bytes are consumed, remainder is nil. The returned
// remainder is a newly allocated copy, not a sub-slice of data.
func SplitFramesPartial(data []byte) ([]Frame, []byte) {
	// Fast path: try exact parse (all bytes consumed)
	if result := splitFrom(data, 0, nil); result != nil {
		return result, nil
	}

	// Greedy: consume frames from the front, stop when nothing fits
	var frames []Frame
	pos := 0
	for pos < len(data) {
		candidates := frameCandidates(data[pos:])
		if len(candidates) == 0 {
			break
		}
		found := false
		for _, c := range candidates {
			if pos+c.length <= len(data) && ValidCRC(data[pos:pos+c.length]) {
				frames = append(frames, Frame{
					Data: data[pos : pos+c.length],
					Dir:  c.dir,
				})
				pos += c.length
				found = true
				break
			}
		}
		if !found {
			break
		}
	}

	var remainder []byte
	if pos < len(data) {
		remainder = make([]byte, len(data)-pos)
		copy(remainder, data[pos:])
	}
	return frames, remainder
}

// splitFrom recursively tries to split data[pos:] into frames. Returns nil if
// no clean split is possible.
func splitFrom(data []byte, pos int, acc []Frame) []Frame {
	if pos == len(data) {
		return acc
	}

	candidates := frameCandidates(data[pos:])
	if len(candidates) == 0 {
		return nil
	}

	for _, c := range candidates {
		if pos+c.length > len(data) {
			continue
		}
		frame := Frame{
			Data: data[pos : pos+c.length],
			Dir:  c.dir,
		}
		if !ValidCRC(frame.Data) {
			continue
		}
		if result := splitFrom(data, pos+c.length, append(acc, frame)); result != nil {
			return result
		}
	}
	return nil
}
