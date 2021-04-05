package cipher

import (
	"errors"
)

// MaxConnectionNameLength is max length of connections's name
const MaxConnectionNameLength = 36

// MessageType is type of message (data) in Cipher
type MessageType uint8

const (
	// TypeActivation is type of activation message
	TypeActivation = 0x02

	// TypeSingle is type of single message (message sent to another connection)
	TypeSingle = 0x03

	// TypeGroup is type of group message (message sent to a group of connections)
	TypeGroup = 0x04

	// TypeSingleCached is type of single message (message sent to another connection and cached on system)
	TypeSingleCached = 0x05

	// TypeGroupCached is type of group message (message sent to a group of connections and cached on system)
	TypeGroupCached = 0x06

	// TypeDone is type of done message
	TypeDone = 0x07
)

// Cipher is encrypted message
type Cipher struct {
	MessageID   uint64
	MessageType MessageType
	MessageTag  uint64
	IsFirst     bool
	IsLast      bool
	IsRequest   bool
	IsEncrypted bool
	Name        string // name of receiver or sender
	IV          []byte
	Data        []byte
	AuthenTag   []byte
	Sign        []byte
}

// ParseBytes converts bytes to Cipher
// ID of message: 8 bytes
// Encrypted, First, Last, Request/Response, Tag, Type (3 bits): 1 byte
// Length of Name (nName): 1 byte
// Tag: if flag of tag = 1 then 8 bytes, otherwise 0 byte
// AUTHEN_TAG: if encrypted is true then 16 bytes, otherwise 0 byte
// IV: if encrypted is true then 12 bytes, otherwise 0 byte
// Sign: if encrypted is false then 32 bytes (HMAC-SHA256), otherwise 0 byte
// Name: nName bytes
// Data: remaining bytes
func ParseBytes(buffer []byte) (*Cipher, error) {
	fixedLen := 10
	posAuthenTag := 10
	lenBuffer := len(buffer)
	if lenBuffer < fixedLen {
		return nil, errors.New("Invalid bytes")
	}

	flag := buffer[8]
	isEncrypted := (flag & 0x80) != 0
	msgID :=
		(uint64(buffer[7]) << 56) | (uint64(buffer[6]) << 48) | (uint64(buffer[5]) << 40) | (uint64(buffer[4]) << 32) |
			(uint64(buffer[3]) << 24) | (uint64(buffer[2]) << 16) | (uint64(buffer[1]) << 8) | uint64(buffer[0])
	lenName := int(buffer[9])
	msgTag := uint64(0)
	if (flag & 0x08) != 0 {
		fixedLen += 8
		posAuthenTag += 8
		if lenBuffer < fixedLen {
			return nil, errors.New("Invalid bytes")
		}
		msgTag =
			(uint64(buffer[17]) << 56) | (uint64(buffer[16]) << 48) | (uint64(buffer[15]) << 40) | (uint64(buffer[14]) << 32) |
				(uint64(buffer[13]) << 24) | (uint64(buffer[12]) << 16) | (uint64(buffer[11]) << 8) | uint64(buffer[10])
	}

	if isEncrypted {
		fixedLen += 28 // authenTag (16) + iv (12)
	}
	if lenBuffer < fixedLen+lenName || lenName == 0 || lenName > MaxConnectionNameLength {
		return nil, errors.New("Invalid bytes")
	}

	// Parse AUTHEN_TAG, IV
	var (
		authenTag []byte
		iv        []byte
		sign      []byte
	)
	if isEncrypted {
		authenTag = make([]byte, 16, 16)
		iv = make([]byte, 12, 12)
		posIV := posAuthenTag + 16
		copy(authenTag, buffer[posAuthenTag:posIV])
		copy(iv, buffer[posIV:fixedLen])
	} else {
		posSign := fixedLen
		fixedLen += 32
		if lenBuffer < fixedLen+lenName {
			return nil, errors.New("Invalid bytes")
		}
		sign = make([]byte, 32, 32)
		copy(sign, buffer[posSign:fixedLen])
	}

	// Parse name
	posData := fixedLen + lenName
	name := ""
	if lenName > 0 {
		name = string(buffer[fixedLen:posData])
	}

	// Parse data
	var data []byte
	lenData := lenBuffer - posData
	if lenData > 0 {
		data = make([]byte, lenData, lenData)
		copy(data, buffer[posData:])
	}

	return &Cipher{
		MessageID:   msgID,
		MessageType: MessageType(flag & 0x07),
		MessageTag:  msgTag,
		IsFirst:     (flag & 0x40) != 0,
		IsLast:      (flag & 0x20) != 0,
		IsRequest:   (flag & 0x10) != 0,
		IsEncrypted: isEncrypted,
		Name:        name,
		IV:          iv,
		Data:        data,
		AuthenTag:   authenTag,
		Sign:        sign,
	}, nil
}

// IntoBytes converts Cipher to bytes
func (c *Cipher) IntoBytes() ([]byte, error) {
	if c.IsEncrypted {
		return BuildCipherBytes(
			c.MessageID,
			c.MessageTag,
			c.MessageType,
			c.IsFirst,
			c.IsLast,
			c.IsRequest,
			c.Name,
			c.IV,
			c.Data,
			c.AuthenTag,
		)
	}
	return BuildNoCipherBytes(
		c.MessageID,
		c.MessageTag,
		c.MessageType,
		c.IsFirst,
		c.IsLast,
		c.IsRequest,
		c.Name,
		c.Data,
		c.Sign,
	)
}

// GetRawBytes returns raw bytes of Cipher
func (c *Cipher) GetRawBytes() ([]byte, error) {
	return BuildRawBytes(
		c.MessageID,
		c.MessageTag,
		c.MessageType,
		c.IsEncrypted,
		c.IsFirst,
		c.IsLast,
		c.IsRequest,
		c.Name,
		c.Data,
	)
}

// GetAad returns aad of Cipher
func (c *Cipher) GetAad() ([]byte, error) {
	return BuildAad(
		c.MessageID,
		c.MessageTag,
		c.MessageType,
		c.IsEncrypted,
		c.IsFirst,
		c.IsLast,
		c.IsRequest,
		c.Name,
	)
}

// BuildRawBytes build raw bytes of Cipher
func BuildRawBytes(msgID, msgTag uint64, msgType MessageType, encrypted, first, last, request bool, name string, data []byte) ([]byte, error) {
	lenName := len(name)
	if lenName == 0 || lenName > MaxConnectionNameLength {
		return nil, errors.New("Invalid name")
	}
	lenData := len(data)

	var (
		bEncrypted byte = 0
		bFirst     byte = 0
		bLast      byte = 0
		bRequest   byte = 0
		bUseTag    byte = 0
	)
	if encrypted {
		bEncrypted = 1
	}
	if first {
		bFirst = 1
	}
	if last {
		bLast = 1
	}
	if request {
		bRequest = 1
	}

	fixedLen := 10
	if msgTag > 0 {
		bUseTag = 1
		fixedLen += 8
	}

	buffer := make([]byte, fixedLen+lenName+lenData, fixedLen+lenName+lenData)
	buffer[0] = byte(msgID)
	buffer[1] = byte(msgID >> 8)
	buffer[2] = byte(msgID >> 16)
	buffer[3] = byte(msgID >> 24)
	buffer[4] = byte(msgID >> 32)
	buffer[5] = byte(msgID >> 40)
	buffer[6] = byte(msgID >> 48)
	buffer[7] = byte(msgID >> 56)
	buffer[8] = byte(bEncrypted<<7 | bFirst<<6 | bLast<<5 | bRequest<<4 | bUseTag<<3 | byte(msgType))
	buffer[9] = byte(lenName)
	if msgTag > 0 {
		buffer[10] = byte(msgTag)
		buffer[11] = byte(msgTag >> 8)
		buffer[12] = byte(msgTag >> 16)
		buffer[13] = byte(msgTag >> 24)
		buffer[14] = byte(msgTag >> 32)
		buffer[15] = byte(msgTag >> 40)
		buffer[16] = byte(msgTag >> 48)
		buffer[17] = byte(msgTag >> 56)
	}
	copy(buffer[fixedLen:], []byte(name))
	if lenData > 0 {
		copy(buffer[fixedLen+lenName:], data)
	}

	return buffer, nil
}

// BuildAad build aad of Cipher
func BuildAad(msgID, msgTag uint64, msgType MessageType, encrypted, first, last, request bool, name string) ([]byte, error) {
	lenName := len(name)
	if lenName == 0 || lenName > MaxConnectionNameLength {
		return nil, errors.New("Invalid name")
	}

	var (
		bEncrypted byte = 0
		bFirst     byte = 0
		bLast      byte = 0
		bRequest   byte = 0
		bUseTag    byte = 0
	)
	if encrypted {
		bEncrypted = 1
	}
	if first {
		bFirst = 1
	}
	if last {
		bLast = 1
	}
	if request {
		bRequest = 1
	}

	fixedLen := 10
	if msgTag > 0 {
		bUseTag = 1
		fixedLen += 8
	}

	buffer := make([]byte, fixedLen+lenName, fixedLen+lenName)
	buffer[0] = byte(msgID)
	buffer[1] = byte(msgID >> 8)
	buffer[2] = byte(msgID >> 16)
	buffer[3] = byte(msgID >> 24)
	buffer[4] = byte(msgID >> 32)
	buffer[5] = byte(msgID >> 40)
	buffer[6] = byte(msgID >> 48)
	buffer[7] = byte(msgID >> 56)
	buffer[8] = byte(bEncrypted<<7 | bFirst<<6 | bLast<<5 | bRequest<<4 | bUseTag<<3 | byte(msgType))
	buffer[9] = byte(lenName)
	if msgTag > 0 {
		buffer[10] = byte(msgTag)
		buffer[11] = byte(msgTag >> 8)
		buffer[12] = byte(msgTag >> 16)
		buffer[13] = byte(msgTag >> 24)
		buffer[14] = byte(msgTag >> 32)
		buffer[15] = byte(msgTag >> 40)
		buffer[16] = byte(msgTag >> 48)
		buffer[17] = byte(msgTag >> 56)
	}
	copy(buffer[fixedLen:], []byte(name))

	return buffer, nil
}

// BuildCipherBytes builds bytes of Cipher (encrypted mode)
func BuildCipherBytes(msgID, msgTag uint64, msgType MessageType, first, last, request bool, name string, iv, data, authenTag []byte) ([]byte, error) {
	return buildBytes(msgID, msgTag, msgType, true, first, last, request, name, iv, data, authenTag, make([]byte, 0))
}

// BuildNoCipherBytes builds bytes of Cipher (unencrypted mode)
func BuildNoCipherBytes(msgID, tag uint64, msgType MessageType, first, last, request bool, name string, data, sign []byte) ([]byte, error) {
	empty := make([]byte, 0)
	return buildBytes(msgID, tag, msgType, false, first, last, request, name, empty, data, empty, sign)
}

func buildBytes(msgID, msgTag uint64, msgType MessageType, encrypted, first, last, request bool, name string, iv, data, authenTag, sign []byte) ([]byte, error) {
	lenName := len(name)
	if lenName == 0 || lenName > MaxConnectionNameLength {
		return nil, errors.New("Invalid name")
	}

	lenIV := len(iv)
	lenAuthenTag := len(authenTag)
	lenSign := len(sign)
	if encrypted && (lenAuthenTag != 16 || lenIV != 12) {
		return nil, errors.New("Invalid authen-tag or iv")
	}

	if !encrypted && lenSign != 32 {
		return nil, errors.New("Invaid sign")
	}

	var (
		bEncrypted byte = 0
		bFirst     byte = 0
		bLast      byte = 0
		bRequest   byte = 0
		bUseTag    byte = 0
	)
	if encrypted {
		bEncrypted = 1
	}
	if first {
		bFirst = 1
	}
	if last {
		bLast = 1
	}
	if request {
		bRequest = 1
	}

	fixedLen := 10
	if msgTag > 0 {
		bUseTag = 1
		fixedLen += 8
	}

	lenData := len(data)
	lenBuffer := fixedLen + lenAuthenTag + lenIV + lenSign + lenName + lenData
	buffer := make([]byte, lenBuffer, lenBuffer)
	buffer[0] = byte(msgID)
	buffer[1] = byte(msgID >> 8)
	buffer[2] = byte(msgID >> 16)
	buffer[3] = byte(msgID >> 24)
	buffer[4] = byte(msgID >> 32)
	buffer[5] = byte(msgID >> 40)
	buffer[6] = byte(msgID >> 48)
	buffer[7] = byte(msgID >> 56)
	buffer[8] = byte(bEncrypted<<7 | bFirst<<6 | bLast<<5 | bRequest<<4 | bUseTag<<3 | byte(msgType))
	buffer[9] = byte(lenName)
	if msgTag > 0 {
		buffer[10] = byte(msgTag)
		buffer[11] = byte(msgTag >> 8)
		buffer[12] = byte(msgTag >> 16)
		buffer[13] = byte(msgTag >> 24)
		buffer[14] = byte(msgTag >> 32)
		buffer[15] = byte(msgTag >> 40)
		buffer[16] = byte(msgTag >> 48)
		buffer[17] = byte(msgTag >> 56)
	}
	posData := fixedLen + lenAuthenTag
	if encrypted {
		copy(buffer[fixedLen:], authenTag)
		copy(buffer[posData:], iv)
		posData += lenIV
	} else {
		copy(buffer[fixedLen:], sign)
		posData += lenSign
	}
	copy(buffer[posData:], []byte(name))
	posData += lenName
	if lenData > 0 {
		copy(buffer[posData:], data)
	}
	return buffer, nil
}
