package cryptoauthlib

func (d *Device) Challenge(num []byte) (err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err = nonceBase(d.transport, NONCE_MODE_PASSTHROUGH, 0, num)
	return
}

func (d *Device) ChallengeSeedUpdate(num []byte) (output []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return nonceBase(d.transport, NONCE_MODE_SEED_UPDATE, 0, num)
}

func (d *Device) Nonce(num []byte) (err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	_, err = nonceBase(d.transport, NONCE_MODE_PASSTHROUGH, 0, num)
	return
}

func (d *Device) GenSessionKey(param2 uint16, num []byte) (output []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return nonceBase(d.transport, NONCE_MODE_GEN_SESSION_KEY, param2, num)
}

func (d *Device) NonceLoad(target uint8, num []byte) (err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	mode := NONCE_MODE_PASSTHROUGH | (NONCE_MODE_TARGET_MASK & target)
	switch len(num) {
	case 32:
		mode |= NONCE_MODE_INPUT_LEN_32
	case 64:
		mode |= NONCE_MODE_INPUT_LEN_64
	default:
		return StatusBadParam
	}
	_, err = nonceBase(d.transport, mode, 0, num)
	return
}

func (d *Device) NonceRand(num []byte) (output []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	return nonceBase(d.transport, NONCE_MODE_SEED_UPDATE, 0, num)
}

func nonceBase(t Transport, mode uint8, param2 uint16, num []byte) (result []byte, err error) {
	buf := make([]byte, NONCE_COUNT_LONG_64)
	p := newNonceCommand(buf, mode, param2)

	switch mode & NONCE_MODE_MASK {
	case NONCE_MODE_SEED_UPDATE, NONCE_MODE_NO_SEED_UPDATE, NONCE_MODE_GEN_SESSION_KEY:
		copy(p.data(), num[:NONCE_NUMIN_SIZE])
	case NONCE_MODE_PASSTHROUGH:
		if mode&NONCE_MODE_INPUT_LEN_MASK == NONCE_MODE_INPUT_LEN_64 {
			copy(p.data(), num[:64])
		} else {
			copy(p.data(), num[:32])
		}
	default:
		return nil, StatusBadParam
	}

	if err = p.execute(t); err != nil {
		return
	}

	if buf[ATCA_COUNT_IDX] >= 35 {
		result = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+32]
	}

	return
}
