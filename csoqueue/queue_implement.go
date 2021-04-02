package csoqueue

import (
	"sync/atomic"
	"time"
)

type queueImpl struct {
	cap                  int32
	len                  int32
	items                []*ItemQueue
	bufferRemovedIndices []int32
}

// NewQueue inits a new instance of Queue interface
func NewQueue(cap int32) Queue {
	return &queueImpl{
		cap:                  cap,
		len:                  0,
		items:                make([]*ItemQueue, cap, cap),
		bufferRemovedIndices: make([]int32, 0, cap),
	}
}

// This method needs to be invoked before PushMessage method
func (q *queueImpl) TakeIndex() bool {
	if atomic.AddInt32(&q.len, 1) > q.cap {
		atomic.AddInt32(&q.len, -1)
		return false
	}
	return true
}

// TakeIndex method need to be invoked before this method
func (q *queueImpl) PushMessage(item *ItemQueue) {
	for idx, val := range q.items {
		if val == nil {
			q.items[idx] = item
			break
		}
	}
}

func (q *queueImpl) NextMessage() *ItemQueue {
	var nextItem *ItemQueue
	now := uint64(time.Now().Unix())
	q.bufferRemovedIndices = q.bufferRemovedIndices[:0]
	for idx, item := range q.items {
		if item == nil {
			continue
		}
		if nextItem == nil && (now-item.Timestamp) >= 3 { // resend every 3s
			nextItem = item
			item.Timestamp = now
			item.NumberRetry--
		}
		if item.NumberRetry == 0 {
			q.bufferRemovedIndices = append(q.bufferRemovedIndices, int32(idx))
		}
	}
	for _, idx := range q.bufferRemovedIndices {
		q.items[idx] = nil
		atomic.AddInt32(&q.len, -1)
	}
	return nextItem
}

func (q *queueImpl) ClearMessage(msgID uint64) {
	for idx, item := range q.items {
		if item != nil && item.MsgID == msgID {
			q.items[idx] = nil
			atomic.AddInt32(&q.len, -1)
			break
		}
	}
}
