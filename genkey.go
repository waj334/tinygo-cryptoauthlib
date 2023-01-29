package cryptoauthlib

func (d *Device) GenKey(keyId uint16) (pubKey []byte, err error) {
	return d.GenKeyExt(GENKEY_MODE_PRIVATE, keyId, nil)
}

func (d *Device) GenKeyMac() (pubKey []byte, mac []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	buf := make([]byte, ATCA_PUB_KEY_SIZE+ATCA_PACKET_OVERHEAD+MAC_SIZE)
	p := newGenKeyCommand(buf, GENKEY_MODE_MAC, 0)

	// Execute the command
	if err = p.execute(d.transport); err != nil {
		return
	}

	if int(buf[ATCA_COUNT_IDX]) == (ATCA_PUB_KEY_SIZE + ATCA_PACKET_OVERHEAD + MAC_SIZE) {
		// Return the public key and MAC
		pubKey = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+ATCA_PUB_KEY_SIZE]
		mac = buf[ATCA_RSP_DATA_IDX+ATCA_PUB_KEY_SIZE : ATCA_RSP_DATA_IDX+ATCA_PUB_KEY_SIZE+MAC_SIZE]
	} else {
		err = StatusRxFail
	}

	return
}

func (d *Device) GetPublicKey(keyId uint16) (pubkey []byte, err error) {
	return d.GenKeyExt(GENKEY_MODE_PUBLIC, keyId, nil)
}

func (d *Device) GenKeyExt(mode uint8, keyId uint16, otherData []byte) (pubKey []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	buf := make([]byte, ATCA_PUB_KEY_SIZE+ATCA_CMD_SIZE_MIN)
	p := newGenKeyCommand(buf, mode, keyId)

	// Copy other data into the packet data buffer
	if len(otherData) != 0 {
		copy(p.data(), otherData[:GENKEY_OTHER_DATA_SIZE])
	}

	// Execute the command
	if err = p.execute(d.transport); err != nil {
		return
	}

	if int(buf[ATCA_COUNT_IDX]) == (ATCA_PUB_KEY_SIZE + ATCA_PACKET_OVERHEAD) {
		// Return the public key
		pubKey = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+ATCA_PUB_KEY_SIZE]
	} else {
		err = StatusRxFail
	}
	return
}
