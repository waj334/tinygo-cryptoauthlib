package cryptoauthlib

func (d *Device) IsLocked(zone uint8) (locked bool, err error) {
	var data []byte
	if data, err = d.ReadZone(ATCA_ZONE_CONFIG, 0, 2, 5, ReadWord); err != nil {
		return false, err
	}

	switch zone {
	case LOCK_ZONE_CONFIG:
		locked = data[3] != 0x55
	case LOCK_ZONE_DATA:
		locked = data[2] != 0x55
	default:
		return false, StatusBadParam
	}

	return
}
