package csoproxy

type (
	// Response is format message of HTTP response from Proxy server
	Response struct {
		ReturnCode int32       `json:"returncode"`
		Timestamp  uint64      `json:"timestamp"`
		Data       interface{} `json:"data"`
	}

	// RespExchangeKey is response of exchange-key API from Proxy server
	RespExchangeKey struct {
		GKey      string `json:"g_key"`
		NKey      string `json:"n_key"`
		PublicKey string `json:"pub_key"`
		Sign      string `json:"sign"` // using RSA to validate
	}

	// RespRegisterConnection is response of register-connection API from Proxy server
	RespRegisterConnection struct {
		HubAddress  string `json:"hub_address"`
		TicketID    uint32 `json:"ticket_id"`
		TicketToken string `json:"ticket_token"` // encrypted by AES-GCM
		PublicKey   string `json:"pub_key"`
		IV          string `json:"iv"`
		AuthenTag   string `json:"auth_tag"`
	}
)
