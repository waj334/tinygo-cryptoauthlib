package cryptoauthlib

func (d *Device) GetPublicKey(keyId uint16) (pubkey []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return genKeyBase(d.transport, GENKEY_MODE_PUBLIC, keyId, nil)
}

func genKeyBase(t Transport, mode uint8, keyId uint16, otherData []byte) (pubkey []byte, err error) {
	buf := make([]byte, ATCA_PUB_KEY_SIZE+ATCA_CMD_SIZE_MIN)
	p := newGenKeyCommand(buf, mode, keyId)

	// Copy other data into the packet data buffer
	copy(p.data(), otherData)

	// Execute the command
	if err = p.execute(t); err != nil {
		return
	}

	if int(buf[ATCA_COUNT_IDX]) == (ATCA_PUB_KEY_SIZE + ATCA_PACKET_OVERHEAD) {
		// Return the public key
		pubkey = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+ATCA_PUB_KEY_SIZE]
	} else {
		err = StatusRxFail
	}
	return
}
