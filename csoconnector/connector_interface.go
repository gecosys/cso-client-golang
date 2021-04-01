package csoconnector

// Connector keeps connection to server
type Connector interface {
	Open()
	Listen(cb func(sender string, data []byte) error) error

	SendMessage(recvName string, content []byte, isEncrypted, isCached bool) error
	SendGroupMessage(groupName string, content []byte, isEncrypted, isCached bool) error

	SendMessageAndRetry(recvName string, content []byte, isEncrypted bool, numberRetry int32) error
	SendGroupMessageAndRetry(groupName string, content []byte, isEncrypted bool, numberRetry int32) error
}
