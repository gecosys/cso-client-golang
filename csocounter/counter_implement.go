package csocounter

import (
	"sync/atomic"
)

const NumberBits = 32

type counterImpl struct {
	writeIndex   uint64
	minReadIdx   uint64
	maskReadBits uint32
}

// NewCounter inits a new instance of Counter interface
func NewCounter(writeIndex, minReadIdx uint64, maskReadBits uint32) Counter {
	return &counterImpl{
		writeIndex:   writeIndex - 1,
		minReadIdx:   minReadIdx,
		maskReadBits: maskReadBits,
	}
}

func (c *counterImpl) NextWriteIndex() uint64 {
	return atomic.AddUint64(&c.writeIndex, 1)
}

func (c *counterImpl) MarkReadUnused(idx uint64) {
	if idx < c.minReadIdx {
		return
	}
	if idx >= (c.minReadIdx + NumberBits) {
		return
	}
	mask := uint32(1) << (idx - c.minReadIdx)
	c.maskReadBits &= ^mask
}

func (c *counterImpl) MarkReadDone(idx uint64) bool {
	if idx < c.minReadIdx {
		return false
	}

	if idx >= (c.minReadIdx + NumberBits) {
		c.minReadIdx += NumberBits
		c.maskReadBits = 0
	}

	mask := uint32(1) << (idx - c.minReadIdx)
	if (c.maskReadBits & mask) != 0 {
		return false
	}
	c.maskReadBits |= mask
	return true
}
