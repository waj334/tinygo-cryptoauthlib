package cryptoauthlib

import "crypto/sha256"

func (d *Device) Challenge(num []byte) (err error) {
	_, err = d.NonceExt(NONCE_MODE_PASSTHROUGH, 0, num)
	return
}

func (d *Device) ChallengeSeedUpdate(num []byte) (output []byte, err error) {
	return d.NonceExt(NONCE_MODE_SEED_UPDATE, 0, num)
}

func (d *Device) Nonce(num []byte) (err error) {
	_, err = d.NonceExt(NONCE_MODE_PASSTHROUGH, 0, num)
	return
}

func (d *Device) GenSessionKey(param2 uint16, num []byte) (output []byte, err error) {
	return d.NonceExt(NONCE_MODE_GEN_SESSION_KEY, param2, num)
}

func (d *Device) NonceLoad(target uint8, num []byte) (err error) {
	mode := NONCE_MODE_PASSTHROUGH | (NONCE_MODE_TARGET_MASK & target)
	switch len(num) {
	case 32:
		mode |= NONCE_MODE_INPUT_LEN_32
	case 64:
		mode |= NONCE_MODE_INPUT_LEN_64
	default:
		return StatusBadParam
	}
	_, err = d.NonceExt(mode, 0, num)
	return
}

func (d *Device) NonceRand(num []byte) (output []byte, err error) {
	return d.NonceExt(NONCE_MODE_SEED_UPDATE, 0, num)
}

func (d *Device) NonceExt(mode uint8, param2 uint16, num []byte) (result []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

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

	if err = p.execute(d.transport); err != nil {
		return
	}

	if buf[ATCA_COUNT_IDX] >= 35 {
		result = buf[ATCA_RSP_DATA_IDX : ATCA_RSP_DATA_IDX+32]
	}

	return
}

func swNonce(mode uint8, zero uint16, num []byte, randIn []byte, tempKeyIn *tempKey) (randOut []byte, tempKeyOut *tempKey, err error) {
	if len(num) == 0 {
		return nil, nil, StatusBadParam
	}

	switch mode & NONCE_MODE_MASK {
	case NONCE_MODE_SEED_UPDATE, NONCE_MODE_NO_SEED_UPDATE:
		tempKeyIn.is64 = false
		if zero&NONCE_ZERO_CALC_MASK == NONCE_ZERO_CALC_TEMPKEY {
			copy(tempKeyIn.value[:], randIn)
		} else {
			pos := 0
			buf := make([]byte, 55)
			pos += copy(buf, randIn[:RANDOM_NUM_SIZE])
			pos += copy(buf[pos:], num[:NONCE_NUMIN_SIZE])
			buf[pos] = ATCA_NONCE
			buf[pos+1] = mode

			// Calculate SHA256
			dig := sha256.Sum256(buf)
			copy(tempKeyIn.value[:], dig[:])

			// Update tempKey flags
			tempKeyIn.sourceFlag = 0
			tempKeyIn.keyId = 0
			tempKeyIn.genDigData = 0
			tempKeyIn.noMacFlag = 0
			tempKeyIn.valid = true
		}
	}

	return randIn, tempKeyOut, nil
}
