package csoproxy

// Proxy interacts with Proxy server
type Proxy interface {
	ExchangeKey(projectID, uniqueName string) (*RespExchangeKey, error)
	RegisterConnection(projectID, projectToken, uniqueName, publicKey, iv, authenTag string) (*RespRegisterConnection, error)
}
