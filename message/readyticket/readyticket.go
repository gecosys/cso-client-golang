package readyticket

import "errors"

// ReadyTicket is information of ready ticket
type ReadyTicket struct {
	IsReady bool
}

// ParseBytes converts bytes to ReadyTicket
// Flag is_ready: 1 byte
func ParseBytes(buffer []byte) (*ReadyTicket, error) {
	if len(buffer) != 1 {
		return nil, errors.New("Invalid bytes")
	}
	return &ReadyTicket{
		IsReady: buffer[0] == 1,
	}, nil
}

// BuildBytes returns bytes of ReadyTicket
func BuildBytes(isReady bool) ([]byte, error) {
	buffer := make([]byte, 1, 1)
	buffer[0] = 0
	if isReady {
		buffer[0] = 1
	}
	return buffer, nil
}
