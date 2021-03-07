package csoproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"

	"github.com/gecosys/cso-client-golang/config"
	"github.com/gecosys/cso-client-golang/message/ticket"
	"github.com/gecosys/cso-client-golang/utils"
	jsoniter "github.com/json-iterator/go"
)

// proxyImpl is not a thread-safe, just use it on a single thread
type proxyImpl struct {
	conf                       config.Config
	respHTTP                   *response
	respDataExchangeKey        *respExchangeKey
	respDataRegisterConnection *respRegisterConnection
}

// NewProxy inits a new instance of Proxy interface
func NewProxy(conf config.Config) Proxy {
	return &proxyImpl{
		conf:                       conf,
		respHTTP:                   new(response),
		respDataExchangeKey:        new(respExchangeKey),
		respDataRegisterConnection: new(respRegisterConnection),
	}
}

// ExchangeKey gets the public keys of connection
func (proxy *proxyImpl) ExchangeKey(projectID, uniqueName string) (*ServerKey, error) {
	url := fmt.Sprintf("%s/exchange-key", proxy.conf.GetCSOAddress())

	req := make(map[string]interface{})
	req["project_id"] = projectID
	req["unique_name"] = uniqueName

	buf, err := jsoniter.ConfigFastest.Marshal(&req)
	if err != nil {
		return nil, err
	}

	httpResp, err := http.Post(url, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		return nil, err
	}

	defer httpResp.Body.Close()

	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	err = jsoniter.ConfigFastest.Unmarshal(body, &proxy.respHTTP)
	if err != nil {
		return nil, err
	}
	if proxy.respHTTP.ReturnCode != 1 {
		return nil, errors.New(proxy.respHTTP.Data.(string))
	}

	data, err := jsoniter.ConfigFastest.Marshal(proxy.respHTTP.Data.(map[string]interface{}))
	if err != nil {
		return nil, err
	}

	// Parse response
	err = jsoniter.ConfigFastest.Unmarshal(data, &proxy.respDataExchangeKey)
	if err != nil {
		return nil, err
	}

	// Parse signature base64
	sign, err := base64.StdEncoding.DecodeString(proxy.respDataExchangeKey.Sign)
	if err != nil {
		return nil, err
	}

	// Verify DH keys with the signature
	gKeyBytes := []byte(proxy.respDataExchangeKey.GKey)
	nKeyBytes := []byte(proxy.respDataExchangeKey.NKey)
	serverPubKeyBytes := []byte(proxy.respDataExchangeKey.PublicKey)
	lenGKey := len(gKeyBytes)
	lenGNKey := lenGKey + len(nKeyBytes)
	lenBuffer := lenGNKey + len(serverPubKeyBytes)
	buffer := make([]byte, lenBuffer, lenBuffer)
	copy(buffer, gKeyBytes)
	copy(buffer[lenGKey:], nKeyBytes)
	copy(buffer[lenGNKey:], serverPubKeyBytes)
	err = utils.VerifyRSASign(proxy.conf.GetCSOPublicKey(), sign, buffer)
	if err != nil {
		return nil, err
	}

	// Parse DH keys to BigInt
	isOk := false
	gKey, isOk := new(big.Int).SetString(proxy.respDataExchangeKey.GKey, 10)
	if !isOk {
		err = errors.New("Invalid GKey")
		return nil, err
	}
	nKey, isOk := new(big.Int).SetString(proxy.respDataExchangeKey.NKey, 10)
	if !isOk {
		err = errors.New("Invalid NKey")
		return nil, err
	}
	serverPubKey, isOk := new(big.Int).SetString(proxy.respDataExchangeKey.PublicKey, 10)
	if !isOk {
		err = errors.New("Invalid public server-key")
		return nil, err
	}

	return &ServerKey{
		GKey:   gKey,
		NKey:   nKey,
		PubKey: serverPubKey,
	}, nil
}

// RegisterConnection registers connection on a Hub server
func (proxy *proxyImpl) RegisterConnection(projectID, projectToken, connName string, serverKey *ServerKey) (*ServerTicket, error) {
	// Encrypt project-token
	clientPrivKey, err := utils.GenerateDHPrivateKey()
	if err != nil {
		return nil, err
	}

	// Calculate secret key (AES-GCM)
	clientPubKey, err := utils.CalcDHKeys(serverKey.GKey, serverKey.NKey, clientPrivKey)
	if err != nil {
		return nil, err
	}
	clientSecretKey, err := utils.CalcSecretKey(serverKey.NKey, clientPrivKey, serverKey.PubKey)
	if err != nil {
		return nil, err
	}

	// Encrypt project's token by AES-GCM
	decodedToken, err := base64.StdEncoding.DecodeString(projectToken)
	if err != nil {
		return nil, err
	}
	strClientPubKey := clientPubKey.String()
	lenProjectID := len(projectID)
	lenProjectIDConnName := lenProjectID + len(connName)
	lenAAD := lenProjectIDConnName + len(strClientPubKey)
	clientAad := make([]byte, lenAAD, lenAAD)
	copy(clientAad, projectID)
	copy(clientAad[lenProjectID:], connName)
	copy(clientAad[lenProjectIDConnName:], []byte(strClientPubKey))
	cipherIV, cipherAuthenTag, cipherProjectToken, err := utils.EncryptAES(clientSecretKey, decodedToken, clientAad)
	if err != nil {
		return nil, err
	}

	// Invoke API
	url := fmt.Sprintf("%s/register-connection", proxy.conf.GetCSOAddress())

	req := make(map[string]interface{})
	req["project_id"] = projectID
	req["project_token"] = base64.StdEncoding.EncodeToString(cipherProjectToken)
	req["unique_name"] = connName
	req["public_key"] = strClientPubKey
	req["iv"] = base64.StdEncoding.EncodeToString(cipherIV)
	req["authen_tag"] = base64.StdEncoding.EncodeToString(cipherAuthenTag)

	buf, err := jsoniter.ConfigFastest.Marshal(&req)
	if err != nil {
		return nil, err
	}

	httpResp, err := http.Post(url, "application/json", bytes.NewBuffer(buf))
	if err != nil {
		return nil, err
	}

	defer httpResp.Body.Close()

	body, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	err = jsoniter.ConfigFastest.Unmarshal(body, &proxy.respHTTP)
	if err != nil {
		return nil, err
	}
	if proxy.respHTTP.ReturnCode != 1 {
		return nil, errors.New(proxy.respHTTP.Data.(string))
	}

	data, err := jsoniter.ConfigFastest.Marshal(proxy.respHTTP.Data.(map[string]interface{}))
	if err != nil {
		return nil, err
	}

	// Parse response
	err = jsoniter.ConfigFastest.Unmarshal(data, &proxy.respDataRegisterConnection)
	if err != nil {
		return nil, err
	}

	// Decrypt ticket's token
	lenAadAddress := 2 + len(proxy.respDataRegisterConnection.HubAddress)
	serverAad := make([]byte, lenAadAddress+len(proxy.respDataRegisterConnection.PublicKey))
	binary.LittleEndian.PutUint16(serverAad, uint16(proxy.respDataRegisterConnection.TicketID))
	copy(serverAad[2:], proxy.respDataRegisterConnection.HubAddress)
	copy(serverAad[lenAadAddress:], proxy.respDataRegisterConnection.PublicKey)

	serverPubKey, isOk := new(big.Int).SetString(proxy.respDataRegisterConnection.PublicKey, 10)
	if !isOk {
		err = errors.New("Invalid public hub-key")
		return nil, err
	}
	serverSecretKey, err := utils.CalcSecretKey(serverKey.NKey, clientPrivKey, serverPubKey)
	if err != nil {
		return nil, err
	}
	serverIv, err := base64.StdEncoding.DecodeString(proxy.respDataRegisterConnection.IV)
	if err != nil {
		return nil, err
	}
	serverAuthenTag, err := base64.StdEncoding.DecodeString(proxy.respDataRegisterConnection.AuthenTag)
	if err != nil {
		return nil, err
	}
	serverTicketToken, err := base64.StdEncoding.DecodeString(proxy.respDataRegisterConnection.TicketToken)
	if err != nil {
		return nil, err
	}

	ticketToken, err := utils.DecryptAES(serverSecretKey, serverIv, serverAuthenTag, serverTicketToken, serverAad)
	if err != nil {
		return nil, err
	}

	// Build ticket bytes
	ticketBytes, err := ticket.BuildBytes(uint16(proxy.respDataRegisterConnection.TicketID), ticketToken)
	if err != nil {
		return nil, err
	}
	return &ServerTicket{
		HubAddress:      proxy.respDataRegisterConnection.HubAddress,
		TicketID:        proxy.respDataRegisterConnection.TicketID,
		TicketBytes:     ticketBytes,
		ServerSecretKey: serverSecretKey,
	}, err
}
