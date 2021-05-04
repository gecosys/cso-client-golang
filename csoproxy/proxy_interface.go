package csoproxy

// Proxy interacts with Proxy server
type Proxy interface {
	ExchangeKey() (*ServerKey, error)
	RegisterConnection(serverKey *ServerKey) (*ServerTicket, error)
}
