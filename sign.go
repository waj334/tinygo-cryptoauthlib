package cryptoauthlib

func (d *Device) Sign(keyId uint16, message []byte) (signature []byte, err error) {
	//nonceTarget := NONCE_MODE_TARGET_TEMPKEY
	//signSource := SIGN_MODE_SOURCE_TEMPKEY

	// Update RNG seed
	if _, err = d.Random(); err != nil {
		return
	}

	// TODO: The follow lines only apply to ATECC608A/B. Check device model and decide to skip these lines
	nonceTarget := NONCE_MODE_TARGET_MSGDIGBUF
	signSource := SIGN_MODE_SOURCE_MSGDIGBUF
	//***

	if len(message) > 32 {
		// Message is too long
		return nil, StatusBadParam
	}

	// Input message MUST be 32 bytes
	msg := make([]byte, 32)
	copy(msg, message)

	// Load the message into the device
	if err = d.NonceLoad(nonceTarget, msg); err != nil {
		return
	}

	// Acquire the lock now
	d.mutex.Lock()
	defer d.mutex.Unlock()

	// Sign the message
	return signBase(d.transport, uint8(SIGN_MODE_EXTERNAL|signSource), keyId)
}

func (d *Device) SignInternal(keyId uint16, invalidate bool, fullSerialNumber bool) (signature []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	mode := SIGN_MODE_INTERNAL

	if invalidate {
		mode |= SIGN_MODE_INVALIDATE
	}

	if fullSerialNumber {
		mode |= SIGN_MODE_INCLUDE_SN
	}

	return signBase(d.transport, uint8(mode), keyId)
}

func signBase(t Transport, mode uint8, keyId uint16) (signature []byte, err error) {
	buf := make([]byte, 64+ATCA_CMD_SIZE_MIN)
	p := newSignCommand(buf, mode, keyId)

	if err = p.execute(t); err != nil {
		return
	}

	if buf[ATCA_COUNT_IDX] == uint8(ATCA_SIG_SIZE+ATCA_PACKET_OVERHEAD) {
		signature = buf[ATCA_DATA_IDX : ATCA_DATA_IDX+ATCA_SIG_SIZE]
	} else {
		err = StatusRxFail
	}

	return
}
