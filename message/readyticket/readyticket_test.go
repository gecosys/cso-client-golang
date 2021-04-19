package readyticket

import "testing"

func TestParseBytes(t *testing.T) {
	input := []uint8{1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255}
	readyTicket, err := ParseBytes(input)
	if err != nil {
		t.Error("[TestParseBytes] parse bytes failed")
	}
	if readyTicket.IsReady == false {
		t.Error("[TestParseBytes] invalid property IsReady")
	}
	if readyTicket.IdxRead != 18446744073709551615 {
		t.Error("[TestParseBytes] invalid property IdxRead")
	}
	if readyTicket.MaskRead != 4294967295 {
		t.Error("[TestParseBytes] invalid property MaskRead")
	}
	if readyTicket.IdxWrite != 18446744073709551614 {
		t.Error("[TestParseBytes] invalid property IdxWrite")
	}

	input = []uint8{0, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	readyTicket, err = ParseBytes(input)
	if err != nil {
		t.Error("[TestParseBytes] parse bytes failed")
	}
	if readyTicket.IsReady == true {
		t.Error("[TestParseBytes] invalid property IsReady")
	}
	if readyTicket.IdxRead != 18446744073709551614 {
		t.Error("[TestParseBytes] invalid property IdxRead")
	}
	if readyTicket.MaskRead != 4294967295 {
		t.Error("[TestParseBytes] invalid property MaskRead")
	}
	if readyTicket.IdxWrite != 18446744073709551615 {
		t.Error("[TestParseBytes] invalid property IdxWrite")
	}
}
