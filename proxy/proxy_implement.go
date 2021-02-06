package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gecosys/cso-client-golang/config"
	jsoniter "github.com/json-iterator/go"
)

type proxyImpl struct {
	conf config.Config
}

// NewProxy inits a new instance of Proxy interface
func NewProxy(conf config.Config) Proxy {
	return &proxyImpl{
		conf: conf,
	}
}

// ExchangeKey gets the public keys of connection
func (proxy *proxyImpl) ExchangeKey(projectID, uniqueName string) (*RespExchangeKey, error) {
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

	resp := new(Response)
	err = jsoniter.ConfigFastest.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}
	if resp.ReturnCode != 1 {
		return nil, errors.New(resp.Data.(string))
	}

	data, err := jsoniter.ConfigFastest.Marshal(resp.Data.(map[string]interface{}))
	if err != nil {
		return nil, err
	}

	ret := new(RespExchangeKey)
	err = jsoniter.ConfigFastest.Unmarshal(data, &ret)
	return ret, err
}

// RegisterConnection registers connection on a Hub server
// /register-connection
func (proxy *proxyImpl) RegisterConnection(projectID, projectToken, uniqueName, publicKey, iv, authenTag string) (*RespRegisterConnection, error) {
	url := fmt.Sprintf("%s/register-connection", proxy.conf.GetCSOAddress())

	req := make(map[string]interface{})
	req["project_id"] = projectID
	req["project_token"] = projectToken
	req["unique_name"] = uniqueName
	req["public_key"] = publicKey
	req["iv"] = iv
	req["authen_tag"] = authenTag

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

	resp := new(Response)
	err = jsoniter.ConfigFastest.Unmarshal(body, &resp)
	if err != nil {
		return nil, err
	}
	if resp.ReturnCode != 1 {
		return nil, errors.New(resp.Data.(string))
	}

	data, err := jsoniter.ConfigFastest.Marshal(resp.Data.(map[string]interface{}))
	if err != nil {
		return nil, err
	}

	ret := new(RespRegisterConnection)
	err = jsoniter.ConfigFastest.Unmarshal(data, &ret)
	return ret, err
}
