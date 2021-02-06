package ticket

import "errors"

// Ticket is information of register connection
type Ticket struct {
	ID    uint16
	Token []byte
}

// ParseBytes converts bytes to Ticket
// ID: 2 bytes
// Token: next 32 bytes
func ParseBytes(buffer []byte) (*Ticket, error) {
	if len(buffer) != 34 {
		return nil, errors.New("Invalid bytes")
	}
	return &Ticket{
		ID:    (uint16(buffer[1]) << 8) | uint16(buffer[0]),
		Token: buffer[2:],
	}, nil
}

// BuildBytes returns bytes of Ticket
func BuildBytes(id uint16, token []byte) ([]byte, error) {
	if len(token) != 32 {
		return nil, errors.New("Invalid token")
	}
	buffer := make([]byte, 34, 34)
	buffer[0] = byte(id)
	buffer[1] = byte(id >> 8)
	copy(buffer[2:], token)
	return buffer, nil
}
