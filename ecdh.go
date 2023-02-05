package cryptoauthlib

func (d *Device) Ecdh(keyId uint16, pubKey []byte) (pms []byte, err error) {
	if len(pubKey) == 0 {
		return nil, StatusBadParam
	}

	pms, _, err = d.EcdhExt(ECDH_PREFIX_MODE, keyId, pubKey)
	return
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

func (d *Device) EcdhExt(mode uint8, keyId uint16, pubKey []byte) (pms []byte, nonce []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	buf := make([]byte, ECDH_COUNT)
	p := newEcdhCommand(buf, mode, keyId)
	copy(p.data(), pubKey[:ATCA_PUB_KEY_SIZE])

	if err = p.execute(d.transport); err != nil {
		return
	}

	count := int(buf[ATCA_COUNT_IDX])
	if count >= 3+ATCA_KEY_SIZE {

		pms = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+ATCA_KEY_SIZE]
	}

	if count >= 3+ATCA_KEY_SIZE*2 {
		pos := ATCA_RSP_DATA_IDX + ATCA_KEY_SIZE
		nonce = buf[pos : pos+ATCA_KEY_SIZE]
	}

	return
}
