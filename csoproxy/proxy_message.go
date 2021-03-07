package csoproxy

import "math/big"

type (
	// ServerKey is a group of server keys
	ServerKey struct {
		GKey   *big.Int
		NKey   *big.Int
		PubKey *big.Int
	}

	// ServerTicket is an activation ticket from the Hub server
	ServerTicket struct {
		HubAddress      string
		TicketID        uint32
		TicketBytes     []byte
		ServerSecretKey []byte
	}

	// response is format message of HTTP response from the Proxy server
	response struct {
		ReturnCode int32       `json:"returncode"`
		Timestamp  uint64      `json:"timestamp"`
		Data       interface{} `json:"data"`
	}

	// respExchangeKey is response of exchange-key API from the Proxy server
	respExchangeKey struct {
		GKey      string `json:"g_key"`
		NKey      string `json:"n_key"`
		PublicKey string `json:"pub_key"`
		Sign      string `json:"sign"` // using RSA to validate
	}

	// respRegisterConnection is response of register-connection API from the Proxy server
	respRegisterConnection struct {
		HubAddress  string `json:"hub_address"`
		TicketID    uint32 `json:"ticket_id"`
		TicketToken string `json:"ticket_token"` // encrypted by AES-GCM
		PublicKey   string `json:"pub_key"`
		IV          string `json:"iv"`
		AuthenTag   string `json:"auth_tag"`
	}
)
