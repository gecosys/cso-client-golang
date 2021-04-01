package csoconnector

import (
	"errors"
	"log"
	"time"

	"github.com/gecosys/cso-client-golang/config"
	"github.com/gecosys/cso-client-golang/csoconnection"
	"github.com/gecosys/cso-client-golang/csocounter"
	"github.com/gecosys/cso-client-golang/csoparser"
	"github.com/gecosys/cso-client-golang/csoproxy"
	"github.com/gecosys/cso-client-golang/csoqueue"
	"github.com/gecosys/cso-client-golang/message/cipher"
	"github.com/gecosys/cso-client-golang/message/readyticket"
)

type connectorImpl struct {
	conn           csoconnection.Connection
	counter        csocounter.Counter
	chWriteMessage chan *csoqueue.ItemQueue
	isActivated    bool
	queueMessages  csoqueue.Queue
	parser         csoparser.Parser
	proxy          csoproxy.Proxy
	conf           config.Config
}

// NewConnector inits a new instance of Connector interface
func NewConnector(bufferSize uint, parser csoparser.Parser, proxy csoproxy.Proxy, conf config.Config) Connector {
	return &connectorImpl{
		conn:           csoconnection.NewConnection(bufferSize),
		counter:        nil,
		chWriteMessage: make(chan *csoqueue.ItemQueue, bufferSize),
		isActivated:    false,
		queueMessages:  csoqueue.NewQueue(bufferSize),
		parser:         parser,
		proxy:          proxy,
		conf:           conf,
	}
}

func (connector *connectorImpl) Open() {
	var (
		err          error
		serverTicket *csoproxy.ServerTicket
		delayTime    = 3 * time.Second
	)
	for {
		serverTicket, err = connector.prepare()
		if err != nil {
			log.Printf("Error prepare: %s", err.Error())
			time.Sleep(delayTime) // delay `delayTime` seconds before attempting to reconnect to Cloud Socket system
			continue
		}

		// Connect to Cloud Socket system
		connector.parser.SetSecretKey(serverTicket.ServerSecretKey)
		err = connector.conn.Connect(serverTicket.HubAddress)
		if err != nil {
			log.Printf("Error connect: %s", err.Error())
			time.Sleep(delayTime) // delay `delayTime` seconds before attempting to reconnect to Cloud Socket system
			continue
		}

		// Activate the connection
		isDisonnected := false
		connector.isActivated = false
		go func() {
			ticker := time.NewTimer(0)
			for range ticker.C {
				if isDisonnected || connector.isActivated {
					break
				}
				err = connector.activateConnection(serverTicket.TicketID, serverTicket.TicketBytes)
				if err != nil {
					log.Printf("Error activation: %s", err.Error())
				}
				ticker.Reset(delayTime)
			}
			ticker.Stop()
		}()

		err = connector.conn.LoopListen()
		if err != nil {
			log.Printf("Error listen: %s", err.Error())
		}
		isDisonnected = true
		time.Sleep(delayTime) // delay `delayTime` seconds before attempting to reconnect to Cloud Socket system
	}
}

func (connector *connectorImpl) Listen(cb func(sender string, data []byte) error) error {
	chNextMessage, err := connector.conn.GetReadChannel()
	if err != nil {
		return err
	}

	var (
		content     []byte
		messages    [][]byte
		itemQueue   *csoqueue.ItemQueue
		msg         *cipher.Cipher
		readyTicket *readyticket.ReadyTicket
		delayTime   = 3 * time.Second
		emptyData   = []byte{}
	)
	timer := time.NewTimer(delayTime)

	for {
		select {
		case <-timer.C:
			messages = connector.queueMessages.NextMessages()
			if messages == nil {
				timer.Reset(delayTime)
				continue
			}
			for _, content = range messages {
				connector.conn.SendMessage(content)
			}
			timer.Reset(delayTime)
		case itemQueue = <-connector.chWriteMessage:
			connector.queueMessages.PushMessage(itemQueue)
		case content = <-chNextMessage:
			msg, err = connector.parser.ParseReceivedMessage(content)
			if err != nil {
				continue
			}
			switch msg.MessageType {
			case cipher.TypeActivation:
				readyTicket, err = readyticket.ParseBytes(msg.Data)
				if err != nil || !readyTicket.IsReady {
					continue
				}
				connector.isActivated = true
				if connector.counter == nil {
					connector.counter = csocounter.NewCounter(
						readyTicket.IdxWrite,
						readyTicket.IdxRead,
						readyTicket.MaskRead,
					)
				}
			case cipher.TypeUnknown:
				continue
			default:
				if connector.isActivated == false {
					continue
				}

				if msg.MessageID == 0 {
					if msg.IsRequest {
						cb(msg.Name, msg.Data)
					}
					continue
				}

				if msg.IsRequest == false { // response
					connector.queueMessages.ClearMessage(msg.MessageID)
					continue
				}

				if connector.counter.MarkReadDone(msg.MessageTag) {
					err = cb(msg.Name, msg.Data)
					if err != nil {
						connector.counter.MarkReadUnused(msg.MessageTag)
						continue
					}
				}
				connector.sendResponse(msg.MessageID, msg.MessageTag, msg.Name, emptyData, msg.IsEncrypted)
			}
		}
	}
}

func (connector *connectorImpl) SendMessage(recvName string, content []byte, isEncrypted, isCached bool) error {
	if connector.isActivated == false {
		return errors.New("Connection is not ready")
	}
	data, err := connector.parser.BuildMessage(0, 0, recvName, content, isEncrypted, isCached, true, true, true)
	if err != nil {
		return err
	}
	return connector.conn.SendMessage(data)
}

func (connector *connectorImpl) SendGroupMessage(groupName string, content []byte, isEncrypted, isCached bool) error {
	if connector.isActivated == false {
		return errors.New("Connection is not ready")
	}
	data, err := connector.parser.BuildGroupMessage(0, 0, groupName, content, isEncrypted, isCached, true, true, true)
	if err != nil {
		return err
	}
	return connector.conn.SendMessage(data)
}

func (connector *connectorImpl) SendMessageAndRetry(recvName string, content []byte, isEncrypted bool, numberRetry int32) error {
	if connector.isActivated == false {
		return errors.New("Connection is not ready")
	}

	if connector.queueMessages.IsFull() {
		return errors.New("Queue is full")
	}

	msgID := connector.counter.NextWriteIndex()
	data, err := connector.parser.BuildMessage(msgID, 0, recvName, content, isEncrypted, false, true, true, true)
	if err != nil {
		return err
	}

	connector.chWriteMessage <- &csoqueue.ItemQueue{
		MsgID:       msgID,
		Data:        data,
		NumberRetry: numberRetry,
	}
	return nil
}

func (connector *connectorImpl) SendGroupMessageAndRetry(groupName string, content []byte, isEncrypted bool, numberRetry int32) error {
	if connector.isActivated == false {
		return errors.New("Connection is not ready")
	}

	if connector.queueMessages.IsFull() {
		return errors.New("Queue is full")
	}

	msgID := connector.counter.NextWriteIndex()
	data, err := connector.parser.BuildGroupMessage(msgID, 0, groupName, content, isEncrypted, false, true, true, true)
	if err != nil {
		return err
	}

	connector.chWriteMessage <- &csoqueue.ItemQueue{
		MsgID:       msgID,
		Data:        data,
		NumberRetry: numberRetry,
	}
	return nil
}

func (connector *connectorImpl) prepare() (*csoproxy.ServerTicket, error) {
	projectID := connector.conf.GetProjectID()
	connName := connector.conf.GetConnectionName()

	serverKey, err := connector.proxy.ExchangeKey(projectID, connName)
	if err != nil {
		return nil, err
	}

	return connector.proxy.RegisterConnection(
		projectID,
		connector.conf.GetProjectToken(),
		connName,
		serverKey,
	)
}

func (connector *connectorImpl) activateConnection(ticketID uint32, ticketBytes []byte) error {
	data, err := connector.parser.BuildActivateMessage(ticketID, ticketBytes)
	if err != nil {
		return err
	}
	return connector.conn.SendMessage(data)
}

func (connector *connectorImpl) sendResponse(msgID, msgTag uint64, recvName string, data []byte, isEncrypted bool) error {
	data, err := connector.parser.BuildMessage(
		msgID,
		msgTag,
		recvName,
		data,
		isEncrypted,
		false,
		true,
		true,
		false,
	)
	if err != nil {
		return err
	}
	return connector.conn.SendMessage(data)
}
