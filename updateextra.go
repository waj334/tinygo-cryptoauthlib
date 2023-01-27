package cryptoauthlib

func (d *Device) UpdateExtra(mode uint8, value uint16) (err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	buf := make([]byte, UPDATE_COUNT)
	p := newUpdateExtraCommand(buf, mode, value)

	if err = p.execute(d.transport); err != nil {
		return err
	}

	return
}
