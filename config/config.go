package config

import (
	"io/ioutil"

	jsoniter "github.com/json-iterator/go"
)

// Config is configuration of connection
type Config interface {
	GetProjectID() string
	GetProjectToken() string
	GetConnectionName() string
	GetCSOPublicKey() string
	GetCSOAddress() string
}

type configImpl struct {
	ProjectID      string `json:"pid"`
	ProjectToken   string `json:"ptoken"`
	ConnectionName string `json:"cname"`
	CSOPublicKey   string `json:"csopubkey"`
	CSOAddress     string `json:"csoaddr"`
}

// NewConfig inits a new instance of Config
func NewConfig(projectID, projectToken, connName, csoPublicKey, csoAddress string) Config {
	return &configImpl{
		ProjectID:      projectID,
		ProjectToken:   projectToken,
		ConnectionName: connName,
		CSOPublicKey:   csoPublicKey,
		CSOAddress:     csoAddress,
	}
}

// NewConfigFromFile inits a new instance of Config by read cso_key.json file
func NewConfigFromFile(filePath string) (Config, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	conf := new(configImpl)
	err = jsoniter.ConfigFastest.Unmarshal(bytes, conf)
	if err != nil {
		return nil, err
	}
	return conf, nil
}

func (conf *configImpl) GetProjectID() string {
	return conf.ProjectID
}

func (conf *configImpl) GetProjectToken() string {
	return conf.ProjectToken
}

func (conf *configImpl) GetConnectionName() string {
	return conf.ConnectionName
}

func (conf *configImpl) GetCSOPublicKey() string {
	return conf.CSOPublicKey
}

func (conf *configImpl) GetCSOAddress() string {
	return conf.CSOAddress
}
