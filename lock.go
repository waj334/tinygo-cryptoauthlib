package cryptoauthlib

func (d *Device) lock(mode uint8, crc uint16) (err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	buf := make([]byte, LOCK_COUNT)
	p := newLockCommand(buf, mode, crc)

	if err = p.execute(d.transport); err != nil {
		return err
	}

	return
}

func (d *Device) LockConfigZone() (err error) {
	return d.lock(LOCK_ZONE_NO_CRC|LOCK_ZONE_CONFIG, 0)
}

func (d *Device) LockConfigZoneCrc(crc uint16) (err error) {
	return d.lock(LOCK_ZONE_CONFIG, crc)
}

func (d *Device) LockDataSlot(slot uint16) (err error) {
	return d.lock(uint8(slot<<2)|LOCK_ZONE_DATA_SLOT, 0)
}

func (d *Device) LockDataZone() (err error) {
	return d.lock(LOCK_ZONE_NO_CRC|LOCK_ZONE_DATA, 0)
}

func (d *Device) LockDataZoneCrc(crc uint16) (err error) {
	return d.lock(LOCK_ZONE_DATA, crc)
}
