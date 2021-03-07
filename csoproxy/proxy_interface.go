package csoproxy

// Proxy interacts with Proxy server
type Proxy interface {
	ExchangeKey(projectID, uniqueName string) (*ServerKey, error)
	RegisterConnection(projectID, projectToken, connName string, serverKey *ServerKey) (*ServerTicket, error)
}
