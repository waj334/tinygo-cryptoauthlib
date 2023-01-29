package cryptoauthlib

import (
	"bytes"
	"crypto/sha256"
)

func (d *Device) GenDig(zone uint8, keyId uint16, otherData []byte) (err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if otherDataLen := len(otherData); otherDataLen != 0 && otherDataLen != ATCA_BLOCK_SIZE && otherDataLen != ATCA_WORD_SIZE {
		return StatusBadParam
	}

	buf := make([]byte, GENDIG_COUNT+ATCA_BLOCK_SIZE)
	p := newGenDigCommand(buf, zone, keyId, otherData)

	if zone == GENDIG_ZONE_SHARED_NONCE || zone == GENDIG_ZONE_DATA {
		// Copy other data into the packet
		copy(p.data(), otherData)
	}

	// Execute the command
	if err = p.execute(d.transport); err != nil {
		return
	}

	return
}

type genDigParams struct {
	zone       uint8
	keyId      uint16
	slotConf   uint16
	keyConf    uint16
	slotLocked uint8
	counter    uint32
	noMac      bool
	sn         [9]byte
	value      []byte
	otherData  []byte
	tempKey    *tempKey
}

func swGenDig(params *genDigParams) (err error) {
	// Check parameters
	if params.sn[0] == 0 || params.tempKey == nil {
		return StatusBadParam
	}

	if params.zone <= GENDIG_ZONE_DATA && len(params.value) == 0 {
		return StatusBadParam
	}

	if params.zone == GENDIG_ZONE_SHARED_NONCE || (params.zone == GENDIG_ZONE_DATA && params.noMac) && len(params.otherData) == 0 {
		return StatusBadParam
	}

	if params.zone > 5 {
		return StatusBadParam
	}

	buf := bytes.NewBuffer(make([]byte, 0, 55))

	if params.zone == GENDIG_ZONE_SHARED_NONCE {
		if params.keyId&0x8000 != 0 {
			buf.Write(params.tempKey.value[:ATCA_KEY_SIZE])
		} else {
			buf.Write(params.otherData[:ATCA_KEY_SIZE])
		}
	} else if params.zone == GENDIG_ZONE_COUNTER || params.zone == GENDIG_ZONE_KEY_CONFIG {
		// Do nothing since buffer is already all zeros
		// TODO: Remove this condition
	} else {
		buf.Write(params.value[:ATCA_KEY_SIZE])
	}

	if params.zone == GENDIG_ZONE_DATA && params.noMac {
		buf.Write(params.otherData[:ATCA_WORD_SIZE])
	} else {
		buf.WriteByte(ATCA_GENDIG)
		buf.WriteByte(params.zone)
		buf.WriteByte(uint8(params.keyId & 0xFF))

		if params.zone == GENDIG_ZONE_SHARED_NONCE {
			buf.WriteByte(0)
		} else {
			buf.WriteByte(uint8(params.keyId >> 8))
		}
	}

	buf.WriteByte(params.sn[8])
	buf.WriteByte(params.sn[0])
	buf.WriteByte(params.sn[1])

	if params.zone == GENDIG_ZONE_COUNTER {
		buf.WriteByte(0)
		buf.WriteByte(uint8(params.counter & 0xFF))
		buf.WriteByte(uint8(params.counter >> 8))
		buf.WriteByte(uint8(params.counter >> 16))
		buf.WriteByte(uint8(params.counter >> 24))
		buf.Next(20)
	} else if params.zone == GENDIG_ZONE_KEY_CONFIG {
		buf.WriteByte(0)
		buf.WriteByte(uint8(params.slotConf & 0xFF))
		buf.WriteByte(uint8(params.slotConf >> 8))

		buf.WriteByte(uint8(params.keyConf & 0xFF))
		buf.WriteByte(uint8(params.keyConf >> 8))

		buf.WriteByte(params.slotLocked)
		buf.Next(19)
	} else {
		buf.Next(25)
	}

	if params.zone == GENDIG_ZONE_SHARED_NONCE && (params.keyId&0x8000 != 0) {
		buf.Write(params.otherData[:ATCA_KEY_SIZE])
	} else {
		buf.Write(params.tempKey.value[:ATCA_KEY_SIZE])
	}

	// Calculate SHA to get the new temp key
	digest := sha256.Sum256(buf.Bytes())
	copy(params.tempKey.value[:], digest[:])
	params.tempKey.valid = true

	if params.zone == GENDIG_ZONE_DATA && params.keyId <= 15 {
		params.tempKey.genDigData = 1
		params.tempKey.keyId = params.keyId & 0xF
		if params.noMac {
			params.tempKey.noMacFlag = 1
		}
	} else {
		params.tempKey.genDigData = 0
		params.tempKey.keyId = 0
	}

	return
}
