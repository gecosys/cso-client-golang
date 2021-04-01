package csocounter

// Counter counts the number of messages (read/write)
type Counter interface {
	NextWriteIndex() uint64
	MarkReadUnused(idx uint64)
	MarkReadDone(idx uint64) bool
}
