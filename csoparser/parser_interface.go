package csoparser

import "github.com/gecosys/cso-client-golang/message/cipher"

// Parser builds/parses bytes of request/response
type Parser interface {
	SetSecretKey(secretKey []byte)
	ParseReceivedMessage(content []byte) (*cipher.Cipher, error)
	BuildActivateMessage(ticketID uint32, ticketBytes []byte) ([]byte, error)
	BuildMessage(msgID, msgTag uint64, recvName string, content []byte, encrypted, cached, first, last, request bool) ([]byte, error)
	BuildGroupMessage(msgID, msgTag uint64, groupName string, content []byte, encrypted, cached, first, last, request bool) ([]byte, error)
}
