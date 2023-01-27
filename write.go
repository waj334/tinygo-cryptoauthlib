package cryptoauthlib

func (d *Device) write(zone uint8, address uint16, value []byte, mac []byte) (err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if len(value) == 0 {
		return StatusBadParam
	} else if zone&ATCA_ZONE_READWRITE_32 != 0 && len(value) != 32 {
		return StatusBadParam
	} else if zone&ATCA_ZONE_READWRITE_32 == 0 && len(value) != 4 {
		return StatusBadParam
	}

	// NOTE: Maximum size of this command is 71 bytes
	buf := make([]byte, ATCA_CMD_SIZE_MIN+ATCA_BLOCK_SIZE+WRITE_MAC_SIZE)
	p := newWriteCommand(buf, zone, address, mac)

	if zone&ATCA_ZONE_READWRITE_32 != 0 {
		copy(p.data(), value[:ATCA_BLOCK_SIZE])
		if len(mac) != 0 {
			copy(p.data()[ATCA_BLOCK_SIZE:], mac[:ATCA_BLOCK_SIZE])
		}
	} else {
		copy(p.data(), value[:ATCA_WORD_SIZE])
	}

	if err = p.execute(d.transport); err != nil {
		return err
	}

	return
}

func (d *Device) WriteEnc(keyId uint16, block uint8, data []byte, encKey []byte, encKeyId uint16, num []byte) (err error) {
	if len(data) == 0 || len(encKey) == 0 {
		return StatusBadParam
	}

	var sn [9]byte
	var rand []byte
	_tempKey := &tempKey{}

	// Read the serial number that will be used in calculating the MAC
	if sn, err = d.ReadSerialNumber(); err != nil {
		return err
	}

	// Send the random nonce command
	if rand, err = d.NonceRand(num); err != nil {
		return err
	}

	// Calculate the temporary key
	rand, _tempKey, err = swNonce(NONCE_MODE_SEED_UPDATE, 0, num, rand, _tempKey)

	// Send the gendig command
	var otherData [4]byte
	otherData[0] = ATCA_GENDIG
	otherData[1] = GENDIG_ZONE_DATA
	otherData[2] = uint8(encKeyId)
	otherData[3] = uint8(encKeyId >> 8)

	if err = d.GenDig(GENDIG_ZONE_DATA, keyId, otherData[:]); err != nil {
		return
	}

	// Calculate temp key
	gdParams := genDigParams{
		keyId:     encKeyId,
		noMac:     false,
		sn:        sn,
		value:     encKey,
		zone:      GENDIG_ZONE_DATA,
		otherData: otherData[:],
		tempKey:   _tempKey,
	}

	if err = swGenDig(&gdParams); err != nil {
		return
	}

	// Get the address
	var addr uint16
	if addr, err = getAddress(ATCA_ZONE_DATA, keyId, block, 0); err != nil {
		return err
	}

	macParams := writeMacParams{
		zone:          ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32 | ATCA_ZONE_ENCRYPTED,
		keyId:         addr,
		sn:            sn,
		inputData:     data,
		encryptedData: make([]byte, ATCA_KEY_SIZE),
		calculateMac:  true,
		tempKey:       _tempKey,
	}

	if err = swWriteAuthMac(&macParams); err != nil {
		return err
	}

	if err = d.write(macParams.zone, macParams.keyId, macParams.encryptedData, macParams.authMac[:]); err != nil {
		return err
	}

	return
}

func (d *Device) WriteBytesZone(zone uint8, slot uint16, offset int, data []byte) (err error) {
	length := len(data)
	if zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_OTP && zone != ATCA_ZONE_DATA {
		return StatusBadParam
	} else if zone == ATCA_ZONE_DATA && slot > 15 {
		return StatusBadParam
	} else if length == 0 {
		return StatusBadParam
	} else if offset%ATCA_WORD_SIZE != 0 || length%ATCA_WORD_SIZE != 0 {
		return StatusBadParam
	}

	var _zoneSize int
	if _zoneSize, err = zoneSize(zone, slot); err != nil {
		return err
	}

	if offset+length > _zoneSize {
		return StatusBadParam
	}

	currentBlock := offset / ATCA_BLOCK_SIZE
	currentWord := (offset % ATCA_BLOCK_SIZE) / ATCA_WORD_SIZE
	index := 0

	for index < length {
		if currentWord == 0 && length-index > ATCA_BLOCK_SIZE && !(zone == ATCA_ZONE_CONFIG && currentBlock == 2) {
			if err = d.WriteZone(zone, slot, uint8(currentBlock), 0, data[:ATCA_BLOCK_SIZE]); err != nil {
				return err
			}
			index += ATCA_BLOCK_SIZE
			// Re-slice the data slice
			data = data[ATCA_BLOCK_SIZE:]
			currentBlock++
		} else {
			if !(zone == ATCA_ZONE_CONFIG && currentBlock == 2 && currentWord == 5) {
				if err = d.WriteZone(zone, slot, uint8(currentBlock), uint8(currentWord), data[:ATCA_WORD_SIZE]); err != nil {
					return err
				}
			}
			index += ATCA_WORD_SIZE
			// Re-slice the data slice
			data = data[ATCA_WORD_SIZE:]
			currentWord++
			if currentWord == ATCA_BLOCK_SIZE/ATCA_WORD_SIZE {
				currentBlock++
				currentWord = 0
			}
		}
	}

	return
}

func (d *Device) WriteConfigCounter(id uint16, value uint32) (err error) {
	if id > 1 || value > COUNTER_MAX_VALUE {
		return StatusBadParam
	}

	var b [8]byte
	var linA uint16 = 0xFFFF >> 8
	var linB uint16 = 0xFFFF
	if value >= 16 {
		linB >>= uint16(value-16) % 32
	}

	var binA = uint16(value / 32)
	var binB uint16
	if value >= 16 {
		binB = uint16(value-16) / 32
	}

	b[0] = byte(linA >> 8)
	b[1] = byte(linA & 0xFF)
	b[2] = byte(linB >> 8)
	b[3] = byte(linB & 0xFF)

	b[4] = byte(binA >> 8)
	b[5] = byte(binA & 0xFF)
	b[6] = byte(binB >> 8)
	b[7] = byte(binB & 0xFF)

	if err = d.WriteBytesZone(ATCA_ZONE_CONFIG, 0, int(52+id*8), b[:]); err != nil {
		return err
	}

	return
}

func (d *Device) WriteConfigZone(data []byte) (err error) {
	if len(data) == 0 {
		return StatusBadParam
	}

	var configSize int
	if configSize, err = zoneSize(ATCA_ZONE_CONFIG, 0); err != nil {
		return err
	}

	if err = d.WriteBytesZone(ATCA_ZONE_CONFIG, 0, 16, data[16:16+configSize-16]); err != nil {
		return err
	}

	if err = d.UpdateExtra(UPDATE_MODE_USER_EXTRA, uint16(data[84])); err != nil {
		return err
	}

	if err = d.UpdateExtra(UPDATE_MODE_SELECTOR, uint16(data[85])); err != nil {
		return err
	}

	return
}

func (d *Device) WriteZone(zone uint8, slot uint16, block uint8, offset uint8, data []byte) (err error) {
	if dataLen := len(data); dataLen != 4 && dataLen != 32 {
		return StatusBadParam
	} else if dataLen == ATCA_BLOCK_SIZE {
		// Set mode to 32 bit write mode
		zone |= ATCA_ZONE_READWRITE_32
	}

	var addr uint16

	// Get the address of the slots being written to
	if addr, err = getAddress(zone, slot, block, offset); err != nil {
		return err
	}

	// write the data
	if err = d.write(zone, addr, data, nil); err != nil {
		return err
	}

	return
}

func (d *Device) WritePubKey(slot uint16, pubKey []byte) (err error) {
	if len(pubKey) == 64 {
		return StatusBadParam
	}

	formatted := make([]byte, ATCA_KEY_SIZE*3)

	// The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
	// | Block 1                     | Block 2                                      | Block 3       |
	// | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |

	copy(formatted[4:], pubKey[:32])
	copy(formatted[40:], pubKey[32:])

	// write the blocks
	if err = d.WriteZone(ATCA_ZONE_DATA, slot, 0, 0, formatted[:32]); err != nil {
		return err
	}

	if err = d.WriteZone(ATCA_ZONE_DATA, slot, 1, 0, formatted[32:64]); err != nil {
		return err
	}

	if err = d.WriteZone(ATCA_ZONE_DATA, slot, 2, 0, formatted[64:]); err != nil {
		return err
	}

	return
}
