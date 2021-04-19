package cipher

import (
	"math/rand"
	"reflect"
	"testing"
	"time"
)

const gConnName = "goldeneye_technologies"

func TestBuildRawBytes(t *testing.T) {
	expectedRawBytes := []uint8{0, 4, 0, 0, 0, 0, 0, 0, 251, 22, 1, 4, 0, 0, 0, 0, 0, 0, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115, 71, 111, 108, 100, 101, 110, 101, 121, 101, 32, 84, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115}
	rawBytes, err := BuildRawBytes(
		1024,
		1025,
		TypeSingle,
		true,
		true,
		true,
		true,
		gConnName,
		[]byte("Goldeneye Technologies"),
	)
	if err != nil {
		t.Error("[TestBuildRawBytes] build raw bytes failed")
	}

	if reflect.DeepEqual(rawBytes, expectedRawBytes) == false {
		t.Error("[TestBuildRawBytes] invalid RawBytes")
	}

	runCases(func(
		msgID, msgTag uint64,
		msgType MessageType,
		iv,
		data,
		authenTag,
		sign []byte,
		isFirst,
		isLast,
		isRequest,
		isEncrypted bool,
	) {
		cipher := Cipher{
			MessageID:   msgID,
			MessageType: msgType,
			MessageTag:  msgTag,
			IsFirst:     isFirst,
			IsLast:      isLast,
			IsRequest:   isRequest,
			IsEncrypted: isEncrypted,
			Name:        gConnName,
			IV:          iv,
			Data:        data,
			AuthenTag:   authenTag,
			Sign:        sign,
		}

		expectedRawBytes, err = cipher.GetRawBytes()
		if err != nil {
			t.Error("[TestBuildRawBytes] get raw bytes failed")
		}

		rawBytes, err = BuildRawBytes(
			msgID,
			msgTag,
			msgType,
			isEncrypted,
			isFirst,
			isLast,
			isRequest,
			gConnName,
			data,
		)
		if err != nil {
			t.Error("[TestBuildRawBytes] build raw bytes failed")
		}

		if reflect.DeepEqual(rawBytes, expectedRawBytes) == false {
			t.Error("[TestBuildRawBytes] invalid RawBytes")
		}
	})
}

func TestBuildAad(t *testing.T) {
	expectedAad := []uint8{0, 4, 0, 0, 0, 0, 0, 0, 251, 22, 1, 4, 0, 0, 0, 0, 0, 0, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115}
	aad, err := BuildAad(
		1024,
		1025,
		TypeSingle,
		true,
		true,
		true,
		true,
		gConnName,
	)
	if err != nil {
		t.Error("[TestBuildAad] build aad failed")
	}

	if reflect.DeepEqual(aad, expectedAad) == false {
		t.Error("[TestBuildAad] invalid Aad")
	}

	runCases(func(
		msgID, msgTag uint64,
		msgType MessageType,
		iv,
		data,
		authenTag,
		sign []byte,
		isFirst,
		isLast,
		isRequest,
		isEncrypted bool,
	) {
		cipher := Cipher{
			MessageID:   msgID,
			MessageType: msgType,
			MessageTag:  msgTag,
			IsFirst:     isFirst,
			IsLast:      isLast,
			IsRequest:   isRequest,
			IsEncrypted: isEncrypted,
			Name:        gConnName,
			IV:          iv,
			Data:        data,
			AuthenTag:   authenTag,
			Sign:        sign,
		}

		expectedAad, err = cipher.GetAad()
		if err != nil {
			t.Error("[TestBuildAad] get aad failed")
		}

		aad, err = BuildAad(
			msgID,
			msgTag,
			msgType,
			isEncrypted,
			isFirst,
			isLast,
			isRequest,
			gConnName,
		)
		if err != nil {
			t.Error("[TestBuildAad] build aad failed")
		}

		if reflect.DeepEqual(aad, expectedAad) == false {
			t.Error("[TestBuildAad] invalid Aad")
		}
	})
}

func TestIntoBytes(t *testing.T) {
	runCases(func(
		msgID, msgTag uint64,
		msgType MessageType,
		iv,
		data,
		authenTag,
		sign []byte,
		isFirst,
		isLast,
		isRequest,
		isEncrypted bool,
	) {
		cipher := Cipher{
			MessageID:   msgID,
			MessageType: msgType,
			MessageTag:  msgTag,
			IsFirst:     isFirst,
			IsLast:      isLast,
			IsRequest:   isRequest,
			IsEncrypted: isEncrypted,
			Name:        gConnName,
			IV:          iv,
			Data:        data,
			AuthenTag:   authenTag,
			Sign:        sign,
		}

		bytes, err := cipher.IntoBytes()
		if err != nil {
			t.Error("[TestIntoBytes] into bytes failed")
		}

		parsedCipher, err := ParseBytes(bytes)
		if err != nil {
			t.Error("[TestIntoBytes] parse bytes failed")
		}

		if cipher.IsEncrypted != parsedCipher.IsEncrypted {
			t.Error("[TestIntoBytes] invalid property IsEncrypted")
		}

		if cipher.IsFirst != parsedCipher.IsFirst {
			t.Error("[TestIntoBytes] invalid property IsFirst")
		}

		if cipher.IsLast != parsedCipher.IsLast {
			t.Error("[TestIntoBytes] invalid property IsLast")
		}

		if cipher.IsRequest != parsedCipher.IsRequest {
			t.Error("[TestIntoBytes] invalid property IsRequest")
		}

		if cipher.MessageID != parsedCipher.MessageID {
			t.Error("[TestIntoBytes] invalid property MessageID")
		}

		if cipher.MessageTag != parsedCipher.MessageTag {
			t.Error("[TestIntoBytes] invalid property MessageTag")
		}

		if cipher.MessageType != parsedCipher.MessageType {
			t.Error("[TestIntoBytes] invalid property MessageType")
		}

		if cipher.Name != parsedCipher.Name {
			t.Error("[TestIntoBytes] invalid property Name")
		}

		if isEncrypted {
			if reflect.DeepEqual(cipher.IV, parsedCipher.IV) == false {
				t.Error("[TestIntoBytes] invalid property IV")
			}

			if reflect.DeepEqual(cipher.AuthenTag, parsedCipher.AuthenTag) == false {
				t.Error("[TestIntoBytes] invalid property AuthenTag")
			}
		} else if reflect.DeepEqual(cipher.Sign, parsedCipher.Sign) == false {
			t.Error("[TestIntoBytes] invalid property Sign")
		}

		aad, err := cipher.GetAad()
		if err != nil {
			t.Error("[TestIntoBytes] get aad failed")
		}

		parsedAad, err := parsedCipher.GetAad()
		if err != nil {
			t.Error("[TestIntoBytes] get aad from parsed cipher failed")
		}

		if reflect.DeepEqual(aad, parsedAad) == false {
			t.Error("[TestIntoBytes] invalid property Aad")
		}

		if reflect.DeepEqual(cipher.Data, parsedCipher.Data) == false {
			t.Error("[TestIntoBytes] invalid property Data")
		}
	})
}

func TestParseCipherBytes(t *testing.T) {
	// Cipher
	expectedIsEncrypted := true
	expectedIsFirst := true
	expectedIsLast := true
	expectedIsRequest := true
	expectedMessageID := uint64(1024)
	expectedMessageTag := uint64(1025)
	expectedMessageType := TypeSingle
	expectedName := gConnName
	// expectedSign := TypeSingle
	epxectedIV := []uint8{52, 69, 113, 36, 207, 171, 168, 50, 162, 40, 224, 187}
	epxectedAuthenTag := []uint8{106, 232, 205, 181, 53, 106, 177, 50, 190, 131, 144, 7, 101, 44, 27, 45}
	expectedData := []byte("Goldeneye Technologies")
	expectedAad := []uint8{0, 4, 0, 0, 0, 0, 0, 0, 251, 22, 1, 4, 0, 0, 0, 0, 0, 0, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115}

	input := []uint8{0, 4, 0, 0, 0, 0, 0, 0, 251, 22, 1, 4, 0, 0, 0, 0, 0, 0, 106, 232, 205, 181, 53, 106, 177, 50, 190, 131, 144, 7, 101, 44, 27, 45, 52, 69, 113, 36, 207, 171, 168, 50, 162, 40, 224, 187, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115, 71, 111, 108, 100, 101, 110, 101, 121, 101, 32, 84, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115}
	cipher, err := ParseBytes(input)
	if err != nil {
		t.Error("[TestParseCipherBytes] parse bytes failed")
	}

	if cipher.IsEncrypted != expectedIsEncrypted {
		t.Error("[TestParseCipherBytes] invalid property IsEncrypted")
	}

	if cipher.IsFirst != expectedIsFirst {
		t.Error("[TestParseCipherBytes] invalid property IsFirst")
	}

	if cipher.IsLast != expectedIsLast {
		t.Error("[TestParseCipherBytes] invalid property IsLast")
	}

	if cipher.IsRequest != expectedIsRequest {
		t.Error("[TestParseCipherBytes] invalid property IsRequest")
	}

	if cipher.MessageID != expectedMessageID {
		t.Error("[TestParseCipherBytes] invalid property MessageID")
	}

	if cipher.MessageTag != expectedMessageTag {
		t.Error("[TestParseCipherBytes] invalid property MessageTag")
	}

	if int(cipher.MessageType) != expectedMessageType {
		t.Error("[TestParseCipherBytes] invalid property MessageType")
	}

	if cipher.Name != expectedName {
		t.Error("[TestParseCipherBytes] invalid property Name")
	}

	if reflect.DeepEqual(cipher.IV, epxectedIV) == false {
		t.Error("[TestParseCipherBytes] invalid property IV")
	}

	if reflect.DeepEqual(cipher.AuthenTag, epxectedAuthenTag) == false {
		t.Error("[TestParseCipherBytes] invalid property AuthenTag")
	}

	aad, err := cipher.GetAad()
	if err != nil {
		t.Error("[TestParseCipherBytes] get aad failed")
	}

	if reflect.DeepEqual(aad, expectedAad) == false {
		t.Error("[TestParseCipherBytes] invalid property Aad")
	}

	if reflect.DeepEqual(cipher.Data, expectedData) == false {
		t.Error("[TestParseCipherBytes] invalid property Data")
	}
}

func TestParseNoCipherBytes(t *testing.T) {
	// Cipher
	expectedIsEncrypted := false
	expectedIsFirst := true
	expectedIsLast := true
	expectedIsRequest := true
	expectedMessageID := uint64(1024)
	expectedMessageTag := uint64(1025)
	expectedMessageType := TypeSingle
	expectedName := gConnName
	expectedAad := []uint8{0, 4, 0, 0, 0, 0, 0, 0, 123, 22, 1, 4, 0, 0, 0, 0, 0, 0, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115}
	epxectedSign := []uint8{140, 57, 139, 30, 167, 65, 206, 46, 33, 131, 181, 152, 42, 206, 205, 79, 59, 223, 16, 25, 61, 95, 68, 163, 49, 147, 106, 188, 66, 151, 202, 88}
	expectedData := []byte("Goldeneye Technologies")

	input := []uint8{0, 4, 0, 0, 0, 0, 0, 0, 123, 22, 1, 4, 0, 0, 0, 0, 0, 0, 140, 57, 139, 30, 167, 65, 206, 46, 33, 131, 181, 152, 42, 206, 205, 79, 59, 223, 16, 25, 61, 95, 68, 163, 49, 147, 106, 188, 66, 151, 202, 88, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115, 71, 111, 108, 100, 101, 110, 101, 121, 101, 32, 84, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115}
	cipher, err := ParseBytes(input)
	if err != nil {
		t.Error("[TestParseNoCipherBytes] parse bytes failed")
	}

	if cipher.IsEncrypted != expectedIsEncrypted {
		t.Error("[TestParseNoCipherBytes] invalid property IsEncrypted")
	}

	if cipher.IsFirst != expectedIsFirst {
		t.Error("[TestParseNoCipherBytes] invalid property IsFirst")
	}

	if cipher.IsLast != expectedIsLast {
		t.Error("[TestParseNoCipherBytes] invalid property IsLast")
	}

	if cipher.IsRequest != expectedIsRequest {
		t.Error("[TestParseNoCipherBytes] invalid property IsRequest")
	}

	if cipher.MessageID != expectedMessageID {
		t.Error("[TestParseNoCipherBytes] invalid property MessageID")
	}

	if cipher.MessageTag != expectedMessageTag {
		t.Error("[TestParseNoCipherBytes] invalid property MessageTag")
	}

	if int(cipher.MessageType) != expectedMessageType {
		t.Error("[TestParseNoCipherBytes] invalid property MessageType")
	}

	if cipher.Name != expectedName {
		t.Error("[TestParseNoCipherBytes] invalid property Name")
	}

	if reflect.DeepEqual(cipher.Sign, epxectedSign) == false {
		t.Error("[TestParseNoCipherBytes] invalid property Sign")
	}

	aad, err := cipher.GetAad()
	if err != nil {
		t.Error("[TestParseNoCipherBytes] get aad failed")
	}

	if reflect.DeepEqual(aad, expectedAad) == false {
		t.Error("[TestParseNoCipherBytes] invalid property Aad")
	}

	if reflect.DeepEqual(cipher.Data, expectedData) == false {
		t.Error("[TestParseNoCipherBytes] invalid property Data")
	}
}

func runCases(runner func(msgID, msgTag uint64, msgType MessageType, iv, data, authenTag, sign []byte, isFirst, isLast, isRequest, isEncrypted bool)) {
	rand.Seed(time.Now().Unix())

	isEncrypted := true
	msgTypes := []MessageType{
		TypeActivation,
		TypeDone,
		TypeGroup,
		TypeGroupCached,
		TypeSingle,
		TypeSingleCached,
	}
	flagsTables := [][]bool{
		{true, true, true}, // first, last, request
		{false, true, true},
		{true, false, true},
		{true, true, false},
		{false, false, true},
		{true, false, false},
		{false, true, false},
		{false, false, false},
	}

	for i := 0; i < 2; i++ {
		isEncrypted = !isEncrypted
		for _, msgType := range msgTypes {
			for _, flagsTable := range flagsTables {
				iv := make([]byte, 12)
				data := make([]byte, 1024)
				authenTag := make([]byte, 16)
				sign := make([]byte, 32)
				msgID := rand.Uint64()
				msgTag := rand.Uint64()
				rand.Read(iv)
				rand.Read(data)
				rand.Read(authenTag)
				rand.Read(sign)

				isFirst := flagsTable[0]
				isLast := flagsTable[1]
				isRequest := flagsTable[2]
				runner(
					msgID,
					msgTag,
					msgType,
					iv,
					data,
					authenTag,
					sign,
					isFirst,
					isLast,
					isRequest,
					isEncrypted,
				)
			}
		}
	}
}
