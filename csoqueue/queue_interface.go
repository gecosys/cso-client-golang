package csoqueue

type Queue interface {
	// Method can invoke on many threads
	// This method needs to be invoked before PushMessage method
	TakeIndex() bool

	// Methods need to be invoked on the same thread
	PushMessage(item *ItemQueue)
	NextMessage() *ItemQueue
	ClearMessage(msgID uint64)
}
