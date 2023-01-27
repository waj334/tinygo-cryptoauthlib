package cryptoauthlib

func (d *Device) Verify(mode uint8, keyId uint16, signature []byte, pubKey []byte, otherData []byte) (mac []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	verifyMode := mode & VERIFY_MODE_MASK

	if (verifyMode == VERIFY_MODE_EXTERNAL && len(pubKey) == 0) || len(signature) == 0 {
		return nil, StatusBadParam
	}

	if (verifyMode == VERIFY_MODE_VALIDATE || verifyMode == VERIFY_MODE_INVALIDATE) && len(otherData) == 0 {
		return nil, StatusBadParam
	}

	buf := make([]byte, VERIFY_256_EXTERNAL_COUNT)
	p := newVerifyCommand(buf, mode, keyId)
	copy(p.data(), signature[:ATCA_SIG_SIZE])

	if verifyMode == VERIFY_MODE_EXTERNAL {
		copy(p.data()[ATCA_SIG_SIZE:], pubKey)
	} else if len(otherData) != 0 {
		copy(p.data()[ATCA_SIG_SIZE:], otherData[:VERIFY_OTHER_DATA_SIZE])
	}

	// Execute the command
	if err = p.execute(d.transport); err != nil {
		return
	}

	if buf[ATCA_COUNT_IDX] == uint8(ATCA_PACKET_OVERHEAD+MAC_SIZE) {
		mac = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+MAC_SIZE]
	}

	return
}

func (d *Device) VerifyExternal(message, signature, pubKey []byte) (verified bool, err error) {
	// NOTE: This method only supports ATECC608A/B
	nonceTarget := NONCE_MODE_TARGET_MSGDIGBUF
	verifySource := VERIFY_MODE_SOURCE_MSGDIGBUF

	if err = d.NonceLoad(nonceTarget, message); err != nil {
		return
	}

	if _, err = d.Verify(VERIFY_MODE_EXTERNAL|verifySource, VERIFY_KEY_P256, signature, pubKey, nil); err == StatusCheckmacVerifyFailed {
		// Verify failed, but command is successful
		return false, nil
	} else if err != nil {
		return
	}

	return true, nil
}
