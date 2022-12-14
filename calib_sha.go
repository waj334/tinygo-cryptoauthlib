package cryptoauthlib

type SHA256Context struct {
	messageSize int
	blockSize   int
	block       [ATCA_BLOCK_SIZE]byte
}

func (s *SHA256Context) startSHA(t Transport) (err error) {
	_, err = shaBase(t, SHA_MODE_SHA256_START, 0, nil)
	return
}

func (s *SHA256Context) updateSHA(t Transport, data []byte) (err error) {
	dataLen := len(data)
	remaining := ATCA_SHA256_BLOCK_SIZE - s.blockSize
	copyLen := dataLen
	if len(data) > remaining {
		copyLen = remaining
	}

	// Copy data into current block
	copy(s.block[s.blockSize:], data[:copyLen])

	if s.blockSize+dataLen < ATCA_SHA256_BLOCK_SIZE {
		// Not enough data to finish off the current block
		s.blockSize += dataLen
		return nil // Should be equivalent to success
	}

	// Process the current block
	if _, err = shaBase(t, SHA_MODE_SHA256_UPDATE, 64, s.block[:]); err != nil {
		return
	}

	// Process any additional blocks
	dataLen -= copyLen
	blockCount := dataLen / ATCA_SHA256_BLOCK_SIZE
	for i := 0; i < blockCount; i++ {
		if _, err = shaBase(t, SHA_MODE_SHA256_UPDATE, 64, data[copyLen+i*ATCA_SHA256_BLOCK_SIZE:]); err != nil {
			return
		}
	}

	// Save any remaining data
	s.messageSize += (blockCount + 1) * ATCA_SHA256_BLOCK_SIZE
	s.blockSize = dataLen % ATCA_SHA256_BLOCK_SIZE
	copy(s.block[:], data[copyLen+blockCount*ATCA_SHA256_BLOCK_SIZE:])

	return
}

func (s *SHA256Context) endSHA(t Transport) (digest []byte, err error) {
	// NOTE: No support for ATSHA204A is considered. See calib_hw_sha2_256_finish in atca_sha.c. This method only ports
	// what is in the else block.
	return shaBase(t, SHA_MODE_SHA256_END, uint16(s.blockSize), s.block[:])
}

func (s *SHA256Context) startHMAC(t Transport, keySlot uint16) (err error) {
	_, err = shaBase(t, SHA_MODE_HMAC_START, keySlot, nil)
	return
}

func (s *SHA256Context) updateHMAC(t Transport, data []byte) (err error) {
	dataLen := len(data)
	remaining := ATCA_SHA256_BLOCK_SIZE - s.blockSize
	copyLen := dataLen
	if len(data) > remaining {
		copyLen = remaining
	}

	// Copy data into current block
	copy(s.block[s.blockSize:], data[:copyLen])

	if s.blockSize+dataLen < ATCA_SHA256_BLOCK_SIZE {
		// Not enough data to finish off the current block
		s.blockSize += dataLen
		return nil // Should be equivalent to success
	}

	// Process the current block
	if _, err = shaBase(t, SHA_MODE_HMAC_UPDATE, uint16(ATCA_SHA256_BLOCK_SIZE), s.block[:]); err != nil {
		return
	}

	// Process any additional blocks
	dataLen -= copyLen
	blockCount := dataLen / ATCA_SHA256_BLOCK_SIZE
	for i := 0; i < blockCount; i++ {
		if _, err = shaBase(t, SHA_MODE_HMAC_UPDATE, uint16(ATCA_SHA256_BLOCK_SIZE), data[copyLen+i*ATCA_SHA256_BLOCK_SIZE:]); err != nil {
			return
		}
	}

	// Save any remaining data
	s.messageSize += (blockCount + 1) * ATCA_SHA256_BLOCK_SIZE
	s.blockSize = dataLen % ATCA_SHA256_BLOCK_SIZE
	copy(s.block[:], data[copyLen+blockCount*ATCA_SHA256_BLOCK_SIZE:])

	return
}

func (s *SHA256Context) endHMAC(t Transport, target uint8) (digest []byte, err error) {
	// NOTE: No support for ATSHA204A is considered. See calib_sha_hmac_finish in atca_sha.c.

	//For ATECC608, can be SHA_MODE_TARGET_TEMPKEY, SHA_MODE_TARGET_MSGDIGBUF, or SHA_MODE_TARGET_OUT_ONLY.
	mode := SHA_MODE_608_HMAC_END | target
	return shaBase(t, mode, uint16(s.blockSize), s.block[:])
}

func (d *Device) SHA256(input []byte) (output []byte, err error) {
	var ctx SHA256Context
	if err = ctx.startSHA(d.transport); err != nil {
		return
	}
	if err = ctx.updateSHA(d.transport, input); err != nil {
		return
	}

	if output, err = ctx.endSHA(d.transport); err != nil {
		return
	}

	return
}

func (d *Device) HMAC(input []byte, keySlot uint16, target uint8) (output []byte, err error) {
	var ctx SHA256Context
	if err = ctx.startHMAC(d.transport, keySlot); err != nil {
		return
	}
	if err = ctx.updateHMAC(d.transport, input); err != nil {
		return
	}

	if output, err = ctx.endHMAC(d.transport, target); err != nil {
		return
	}

	return
}

func shaBase(t Transport, mode uint8, length uint16, message []byte) (data []byte, err error) {
	cmdMode := mode & SHA_MODE_MASK
	if cmdMode != SHA_MODE_SHA256_PUBLIC && cmdMode != SHA_MODE_HMAC_START && length > 0 && message == nil {
		return nil, StatusBadParam
	}

	buf := make([]byte, 99+ATCA_CMD_SIZE_MIN)

	// Build the command
	p := newSHACommand(buf, mode, length)

	if cmdMode != SHA_MODE_SHA256_PUBLIC && cmdMode != SHA_MODE_HMAC_START {
		// Copy message into data buffer
		copy(p.data(), message)
	}

	// Execute the command
	if err = p.execute(t); err != nil {
		return
	}

	if count := int(buf[ATCA_COUNT_IDX]); count > 4 {
		// Return slice containing data
		data = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+count]
		return
	} else if count == 4 {
		if err = mapCommandStatus(buf[ATCA_RSP_DATA_IDX]); err != StatusSuccess {
			return nil, err
		}
	}

	return nil, nil
}
