package ticket

import (
	"reflect"
	"testing"
)

func TestParseBytes(t *testing.T) {
	expectedToken := []uint8{213, 132, 113, 225, 37, 37, 160, 13, 148, 229, 56, 218, 115, 1, 210, 66, 139, 49, 12, 110, 98, 125, 191, 231, 51, 72, 235, 166, 185, 76, 66, 238}
	input := []uint8{255, 255, 213, 132, 113, 225, 37, 37, 160, 13, 148, 229, 56, 218, 115, 1, 210, 66, 139, 49, 12, 110, 98, 125, 191, 231, 51, 72, 235, 166, 185, 76, 66, 238}
	ticket, err := ParseBytes(input)
	if err != nil {
		t.Error("[TestParseBytes] parse bytes failed")
	}
	if ticket.ID != 65535 {
		t.Error("[TestParseBytes] invalid ID")
	}
	if reflect.DeepEqual(ticket.Token, expectedToken) == false {
		t.Error("[TestParseBytes] invalid Token")
	}
}
