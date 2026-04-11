package transport

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"time"
)

func encodePaddedFrame(payload []byte, paddingSizes []int, source io.Reader) ([]byte, error) {
	frameLen, err := normalizedFrameSize(payloadLen(payload), paddingSizes, source)
	if err != nil {
		return nil, err
	}

	frame := make([]byte, frameLen)
	binary.BigEndian.PutUint32(frame[:4], uint32(frameLen))
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	copy(frame[frameHeaderSize:], payload)
	return frame, nil
}

func normalizedFrameSize(payloadLen int, paddingSizes []int, source io.Reader) (int, error) {
	minimum := frameHeaderSize + payloadLen
	if minimum > maxFrameSize {
		return 0, errFrameTooLarge
	}

	var candidates []int
	for _, size := range paddingSizes {
		if size >= minimum {
			candidates = append(candidates, size)
		}
	}
	if len(candidates) == 0 {
		return minimum, nil
	}

	index, err := randomInt(source, len(candidates))
	if err != nil {
		return 0, err
	}
	return candidates[index], nil
}

func randomJitter(min, max time.Duration, source io.Reader) (time.Duration, error) {
	if max <= 0 {
		return 0, nil
	}
	if min < 0 {
		min = 0
	}
	if max < min {
		max = min
	}
	if min == 0 && max == 0 {
		return 0, nil
	}

	span := max - min
	if span == 0 {
		return min, nil
	}

	offset, err := randomInt(source, int(span.Milliseconds())+1)
	if err != nil {
		return 0, err
	}
	return min + time.Duration(offset)*time.Millisecond, nil
}

func randomInt(source io.Reader, limit int) (int, error) {
	if limit <= 1 {
		return 0, nil
	}
	if source == nil {
		source = cryptorand.Reader
	}

	nBig, err := cryptorand.Int(source, big.NewInt(int64(limit)))
	if err != nil {
		return 0, err
	}
	return int(nBig.Int64()), nil
}

func payloadLen(payload []byte) int {
	return len(payload)
}
