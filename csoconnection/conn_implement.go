package csoconnection

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
)

// HeaderSize is size of header
const HeaderSize = 2

// BufferSize is size of buffer or body
const BufferSize = 1204

type connectionImpl struct {
	status        Status
	socket        net.Conn
	chNextMessage chan []byte // receive from server
}

// NewConnection inits a new instance of Connection interface
func NewConnection(bufferSize uint) Connection {
	return &connectionImpl{
		status:        StatusPrepare,
		socket:        nil,
		chNextMessage: make(chan []byte, bufferSize),
	}
}

func (conn *connectionImpl) Connect(address string) error {
	if conn.status != StatusPrepare && conn.socket != nil {
		conn.status = StatusPrepare
		conn.socket.Close()
	}

	conn.status = StatusConnecting
	socket, err := net.Dial("tcp", address)
	if err != nil {
		conn.status = StatusPrepare
		return err
	}
	conn.socket = socket
	conn.status = StatusConnected
	return nil
}

func (conn *connectionImpl) LoopListen() error {
	var (
		err           error
		posBuffer     = 0
		nextPosBuffer = 0
		lenHeader     = 0
		lenBody       = 0
		lenBuffer     = 0
		lenMessage    = 0
		buffer        = make([]byte, BufferSize, BufferSize)
		header        = make([]byte, HeaderSize, HeaderSize)
		body          = make([]byte, BufferSize, BufferSize)
	)

	defer func() {
		conn.status = StatusDisconnected
	}()

	for {
		posBuffer = 0
		lenBuffer, err = conn.socket.Read(buffer)
		if err != nil {
			return err
		}
		if lenBuffer <= 0 { // conection closed
			return nil
		}
		for posBuffer < lenBuffer {
			// Read header
			if lenMessage == 0 {
				nextPosBuffer = int(math.Min(float64(posBuffer+HeaderSize-lenHeader), float64(lenBuffer)))
				copy(header[lenHeader:], buffer[posBuffer:nextPosBuffer])
				lenHeader += nextPosBuffer - posBuffer
				posBuffer = nextPosBuffer
				if lenHeader == HeaderSize {
					lenMessage = int(header[1])<<8 | int(header[0])
					lenBody = 0
				}
				continue
			}

			if lenMessage <= 0 || lenMessage > BufferSize {
				lenHeader = 0
				lenMessage = 0
				posBuffer += lenMessage
				continue
			}

			// Read body
			nextPosBuffer = int(math.Min(float64(posBuffer+(lenMessage-lenBody)), float64(lenBuffer)))
			copy(body[lenBody:], buffer[posBuffer:nextPosBuffer])
			lenBody += nextPosBuffer - posBuffer
			posBuffer = nextPosBuffer
			if lenBody != lenMessage {
				continue
			}
			conn.chNextMessage <- body[:lenBody]
			lenMessage = 0
			lenHeader = 0
		}
	}
}

func (conn *connectionImpl) SendMessage(data []byte) error {
	if conn.status != StatusConnected {
		return errors.New("The conenction closed")
	}

	// Build formated data
	lenBytes := len(data)
	lenBuffer := 2 + lenBytes
	buffer := make([]byte, lenBuffer, lenBuffer)
	binary.LittleEndian.PutUint16(buffer, uint16(lenBytes))
	copy(buffer[2:], data)

	// Send message
	var (
		err       error
		n         = 0
		posBuffer = 0
	)
	for posBuffer < lenBuffer {
		n, err = conn.socket.Write(buffer)
		if err != nil {
			conn.socket.Close()
			return err
		}
		if n == 0 {
			conn.socket.Close()
			return errors.New("The conenction closed")
		}
		posBuffer += n
	}
	return nil
}

func (conn *connectionImpl) GetReadChannel() (<-chan []byte, error) {
	return conn.chNextMessage, nil
}
