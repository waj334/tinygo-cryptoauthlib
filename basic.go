package cryptoauthlib

func getAddress(zone uint8, slot uint16, block uint8, offset uint8) (address uint16, err error) {
	zone = zone & 0x03
	if zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_DATA && zone != ATCA_ZONE_OTP {
		return 0, StatusBadParam
	}

	// Mask the offset
	offset = offset & 0x07
	if zone == ATCA_ZONE_CONFIG || zone == ATCA_ZONE_OTP {
		address = uint16(block) << 3
		address |= uint16(offset)
	} else {
		address = slot << 3
		address |= uint16(offset)
		address |= uint16(block) << 8
	}

	return
}

func zoneSize(zone uint8, slot uint16) (size int, err error) {
	switch zone {
	case ATCA_ZONE_CONFIG:
		size = 128
	case ATCA_ZONE_OTP:
		size = 64
	case ATCA_ZONE_DATA:
		if slot < 8 {
			size = 36
		} else if slot == 8 {
			size = 416
		} else if slot < 16 {
			size = 72
		} else {
			return 0, StatusBadParam
		}
	default:
		return 0, StatusBadParam
	}

	return
}
