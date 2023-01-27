package cryptoauthlib

func (d *Device) Ecdh(keyId uint16, pubKey []byte) (pms []byte, err error) {
	if len(pubKey) == 0 {
		return nil, StatusBadParam
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()
	pms, _, err = ecdhBase(d.transport, ECDH_PREFIX_MODE, keyId, pubKey)
	return
}

func (d *Device) EcdhExt(mode uint8, keyId uint16, pubKey []byte) (pms []byte, nonce []byte, err error) {
	if len(pubKey) == 0 {
		return nil, nil, StatusBadParam
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()
	return ecdhBase(d.transport, mode, keyId, pubKey)
}

func (d *Device) EcdhEncrypted(keyId uint16, pubKey []byte, readKey []byte, readKeyId uint16, num []byte) (pms []byte, err error) {
	if pubKey == nil || readKey == nil {
		return nil, StatusBadParam
	}

	// Send the ECDH command with the provided public key
	if _, err = d.Ecdh(keyId, pubKey); err != nil {
		return
	}

	return d.ReadEncrypted(keyId|0x0001, 0, readKey, readKeyId, num)
}

func ecdhBase(t Transport, mode uint8, keyId uint16, pubKey []byte) (pms, nonce []byte, err error) {
	buf := make([]byte, ECDH_COUNT)
	p := newEcdhCommand(buf, mode, keyId)
	copy(p.data(), pubKey[:ATCA_PUB_KEY_SIZE])

	if err = p.execute(t); err != nil {
		return
	}

	if buf[ATCA_COUNT_IDX] >= uint8(3+ATCA_KEY_SIZE) {

		pms = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+ATCA_KEY_SIZE]
	}

	if buf[ATCA_COUNT_IDX] >= uint8(3+ATCA_KEY_SIZE) {
		nonce = buf[ATCA_RSP_DATA_IDX+ATCA_KEY_SIZE : ATCA_RSP_DATA_IDX+(ATCA_KEY_SIZE*2)]
	}

	return
}
