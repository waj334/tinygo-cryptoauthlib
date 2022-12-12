package cryptoauthlib

const (
	blockLen = 32 + ATCA_CMD_SIZE_MIN
	wordLen  = 4 + ATCA_CMD_SIZE_MIN
)

func (d *Device) ReadZone(zone uint8, slot uint16, blockNo uint8, offset uint8, data []byte) (err error) {
	var address uint16

	// The input slice must NOT be nil and MUST be exactly 4 OR 32 bytes long
	if len(data) != wordLen && len(data) != blockLen {
		return StatusBadParam
	}

	// The get address function checks the remaining variables
	if address, err = getAddress(zone, slot, blockNo, offset); err != nil {
		return
	}

	// If there are 32 bytes to read, then OR the bit into the mode
	if len(data) >= blockLen {
		zone = zone | ATCA_ZONE_READWRITE_32
	}

	// Build a read command packet
	packet := newReadCommand(data)
	packet.setParam1(zone)
	packet.setParam2(address)

	// Execute the command
	if err = packet.execute(d.transport); err != nil {
		return
	}

	// Drop status byte
	copy(data, data[1:])

	return
}

func (d *Device) ReadSerialNumber() (result []byte, err error) {
	buf := make([]byte, blockLen)
	if err = d.ReadZone(ATCA_ZONE_CONFIG, 0, 0, 0, buf); err != nil {
		return
	}

	// Return the 9-byte serial number
	result = buf[:9]
	return
}
