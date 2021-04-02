package csoqueue

// ItemQueue is an item in Queue
type ItemQueue struct {
	MsgID       uint64
	MsgTag      uint64
	RecvName    string
	Content     []byte
	IsEncrypted bool
	IsCached    bool
	IsFirst     bool
	IsLast      bool
	IsRequest   bool
	IsGroup     bool
	NumberRetry int32
	Timestamp   uint64
}
