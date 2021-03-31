package readyticket

import "errors"

// ReadyTicket is information of ready ticket
type ReadyTicket struct {
	IsReady  bool
	IdxRead  uint64
	MaskRead uint32
	IdxWrite uint64
}

// ParseBytes converts bytes to ReadyTicket
// Flag is_ready: 1 byte
// Idx Read: 8 bytes
// Mark Read: 4 bytes
// Idx Write: 8 bytes
func ParseBytes(buffer []byte) (*ReadyTicket, error) {
	if len(buffer) != 21 {
		return nil, errors.New("Invalid bytes")
	}

	idxRead := (uint64(buffer[8]) << 56) | (uint64(buffer[7]) << 48) | (uint64(buffer[6]) << 40) | (uint64(buffer[5]) << 32) |
		(uint64(buffer[4]) << 24) | (uint64(buffer[3]) << 16) | (uint64(buffer[2]) << 8) | uint64(buffer[1])
	maskRead := (uint32(buffer[12]) << 24) | (uint32(buffer[11]) << 16) | (uint32(buffer[10]) << 8) | uint32(buffer[9])
	idxWrite :=
		(uint64(buffer[20]) << 56) | (uint64(buffer[19]) << 48) | (uint64(buffer[18]) << 40) | (uint64(buffer[17]) << 32) |
			(uint64(buffer[16]) << 24) | (uint64(buffer[15]) << 16) | (uint64(buffer[14]) << 8) | uint64(buffer[13])
	return &ReadyTicket{
		IsReady:  buffer[0] == 1,
		IdxRead:  idxRead,
		MaskRead: maskRead,
		IdxWrite: idxWrite,
	}, nil
}
