package cryptoauthlib

func (d *Device) Random() (output []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	buf := make([]byte, ATCA_BLOCK_SIZE+ATCA_CMD_SIZE_MIN)
	p := newRandomCommand(buf)

	if err = p.execute(d.transport); err != nil {
		return
	}

	if buf[ATCA_COUNT_IDX] != uint8(RANDOM_RSP_SIZE) {
		return nil, StatusRxFail
	}

	output = buf[ATCA_DATA_IDX : ATCA_DATA_IDX+RANDOM_NUM_SIZE]
	return
}
