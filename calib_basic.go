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
