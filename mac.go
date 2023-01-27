package cryptoauthlib

import (
	"bytes"
	"crypto/sha256"
)

type writeMacParams struct {
	zone          uint8
	keyId         uint16
	sn            [9]byte
	inputData     []byte
	encryptedData []byte
	authMac       [32]byte
	calculateMac  bool
	tempKey       *tempKey
}

func swWriteAuthMac(params *writeMacParams) (err error) {
	if len(params.inputData) == 0 || params.tempKey == nil {
		return StatusBadParam
	}

	// Check TempKey validity
	if params.tempKey.noMacFlag != 0 || !params.tempKey.valid {
		params.tempKey.valid = false
		return StatusExecutionError
	}

	// Encrypt by XOR'ing data with the tempkey
	for i := range params.inputData {
		params.encryptedData[i] = params.inputData[i] ^ params.tempKey.value[i]
	}

	if params.calculateMac {
		macInput := make([]byte, 0, 96)
		buf := bytes.NewBuffer(macInput)

		buf.Write(params.tempKey.value[:ATCA_KEY_SIZE])
		buf.WriteByte(ATCA_WRITE)
		buf.WriteByte(params.zone)
		buf.WriteByte(uint8(params.keyId & 0xFF))
		buf.WriteByte(uint8((params.keyId >> 8) & 0xFF))
		buf.WriteByte(params.sn[8])
		buf.WriteByte(params.sn[0])
		buf.WriteByte(params.sn[1])
		buf.Next(25)
		buf.Write(params.inputData[:ATCA_KEY_SIZE])

		// Calculate SHA256
		params.authMac = sha256.Sum256(buf.Bytes())
	}

	return
}
