package csoconnection

// Connection is a connection connects to Cloud Socket system
type Connection interface {
	Connect(address string) error
	LoopListen() error
	SendMessage(data []byte) error
	GetReadChannel() (<-chan []byte, error)
}
