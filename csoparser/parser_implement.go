package csoparser

import (
	"errors"
	"strconv"

	"github.com/gecosys/cso-client-golang/message/cipher"
	"github.com/gecosys/cso-client-golang/utils"
)

type parserImpl struct {
	secretKey []byte
}

// NewParser inits a new instance of Parser interface
func NewParser() Parser {
	return new(parserImpl)
}

func (p *parserImpl) SetSecretKey(secretKey []byte) {
	p.secretKey = secretKey
}

func (p *parserImpl) ParseReceivedMessage(content []byte) (*cipher.Cipher, error) {
	var (
		aad []byte
		msg *cipher.Cipher
	)

	msg, err := cipher.ParseBytes(content)
	if err != nil {
		return nil, err
	}

	if msg.IsEncrypted == false {
		rawBytes, err := msg.GetRawBytes()
		if err != nil {
			return nil, err
		}
		if utils.ValidateHMAC(p.secretKey, rawBytes, msg.Sign) == false {
			return nil, errors.New("Invalid signature")
		}
		return msg, nil
	}

	aad, err = msg.GetAad()
	if err != nil {
		return nil, err
	}

	msg.Data, err = utils.DecryptAES(
		p.secretKey,
		msg.IV,
		msg.AuthenTag,
		msg.Data,
		aad,
	)
	if err != nil {
		return nil, err
	}

	msg.IsEncrypted = false
	msg.IV = msg.IV[:0]
	msg.AuthenTag = msg.AuthenTag[:0]
	return msg, nil
}

func (p *parserImpl) BuildActivateMessage(ticketID uint32, ticketBytes []byte) ([]byte, error) {
	name := strconv.FormatUint(uint64(ticketID), 10)
	aad, err := cipher.BuildAad(0, 0, cipher.TypeActivation, true, true, true, true, name)
	if err != nil {
		return nil, err
	}
	iv, authenTag, data, err := utils.EncryptAES(p.secretKey, ticketBytes, aad)
	if err != nil {
		return nil, err
	}
	return cipher.BuildCipherBytes(0, 0, cipher.TypeActivation, true, true, true, name, iv, data, authenTag)
}

func (p *parserImpl) BuildMessage(msgID, msgTag uint64, recvName string, content []byte, encrypted, cached, first, last, request bool) ([]byte, error) {
	msgType := p.getMessagetype(false, cached)
	if !encrypted {
		rawBytes, err := cipher.BuildRawBytes(msgID, msgTag, msgType, false, first, last, request, recvName, content)
		if err != nil {
			return nil, err
		}
		sign, err := utils.CalcHMAC(p.secretKey, rawBytes)
		if err != nil {
			return nil, err
		}
		return cipher.BuildNoCipherBytes(msgID, msgTag, msgType, first, last, request, recvName, content, sign)
	}

	aad, err := cipher.BuildAad(msgID, msgTag, msgType, true, first, last, request, recvName)
	if err != nil {
		return nil, err
	}

	iv, authenTag, data, err := utils.EncryptAES(p.secretKey, content, aad)
	if err != nil {
		return nil, err
	}

	return cipher.BuildCipherBytes(msgID, msgTag, msgType, first, last, request, recvName, iv, data, authenTag)
}

func (p *parserImpl) BuildGroupMessage(msgID, msgTag uint64, groupName string, content []byte, encrypted, cached, first, last, request bool) ([]byte, error) {
	msgType := p.getMessagetype(true, cached)
	if !encrypted {
		rawBytes, err := cipher.BuildRawBytes(msgID, msgTag, msgType, false, first, last, request, groupName, content)
		if err != nil {
			return nil, err
		}
		sign, err := utils.CalcHMAC(p.secretKey, rawBytes)
		if err != nil {
			return nil, err
		}
		return cipher.BuildNoCipherBytes(msgID, msgTag, msgType, first, last, request, groupName, content, sign)
	}

	aad, err := cipher.BuildAad(msgID, msgTag, msgType, true, first, last, request, groupName)
	if err != nil {
		return nil, err
	}

	iv, authenTag, data, err := utils.EncryptAES(p.secretKey, content, aad)
	if err != nil {
		return nil, err
	}

	return cipher.BuildCipherBytes(msgID, msgTag, msgType, first, last, request, groupName, iv, data, authenTag)
}

func (p *parserImpl) getMessagetype(isGroup, isCached bool) cipher.MessageType {
	if isGroup {
		if isCached {
			return cipher.TypeGroupCached
		}
		return cipher.TypeGroup
	}
	if isCached {
		return cipher.TypeSingleCached
	}
	return cipher.TypeSingle
}
