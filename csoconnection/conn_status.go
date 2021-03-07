package csoconnection

// Status is status of connection
type Status uint8

const (
	// StatusPrepare is status when the connection is setting up.
	StatusPrepare = 0

	// StatusConnecting is status when the connection is connecting to server.
	StatusConnecting = 1

	// StatusConnected is status when the connection connected to server.
	StatusConnected = 2

	// StatusDisconnected is status when the connection closed.
	StatusDisconnected = 3
)
