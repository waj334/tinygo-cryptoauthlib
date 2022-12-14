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
	if len(data) == blockLen {
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

func (d *Device) ReadEncrypted(keyId uint16, block uint8, encKey []byte, encKeyId uint16, numIn [20]byte) (data []byte, err error) {
	// TODO
	return
}

func (d *Device) ReadPublicKey(slot uint16) (pubkey []byte, err error) {
	// Check the value of the slot
	if slot < 8 || slot > 0xF {
		return nil, StatusBadParam
	}

	buf := make([]byte, blockLen)
	data := buf[:ATCA_BLOCK_SIZE]
	pubkey = make([]byte, 0, ATCA_PUB_KEY_SIZE)

	// The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
	// | Block 1                     | Block 2                                      | Block 3       |
	// | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |
	// Read the first block
	if err = d.ReadZone(ATCA_ZONE_DATA, slot, 0, 0, buf); err != nil {
		return nil, err
	}

	// Append to public key skipping padding
	pubkey = append(pubkey, data[4:]...)

	// Read the next block
	if err = d.ReadZone(ATCA_ZONE_DATA, slot, 1, 0, buf); err != nil {
		return
	}

	// Append to public key skipping padding
	pubkey = append(pubkey, data[:4]...)
	pubkey = append(pubkey, data[8:]...)

	// Read the final block
	if err = d.ReadZone(ATCA_ZONE_DATA, slot, 2, 0, buf); err != nil {
		return
	}

	// Append to public key
	pubkey = append(pubkey, data[:8]...)

	return
}

func (d *Device) ReadSerialNumber() (result [9]byte, err error) {
	buf := make([]byte, blockLen)
	if err = d.ReadZone(ATCA_ZONE_CONFIG, 0, 0, 0, buf); err != nil {
		return
	}

	// Bytes [0-3] and [8-12] make up the serial number. Copy those bytes into the output array
	copy(result[:4], buf[:4])
	copy(result[4:], buf[8:13])

	return
}

func (d *Device) ReadSignature(slot uint16) (signature []byte, err error) {
	if slot < 8 || slot > 15 {
		return nil, StatusBadParam
	}

	buf := make([]byte, blockLen)
	data := buf[:ATCA_BLOCK_SIZE]

	// Read the first block
	if err = d.ReadZone(ATCA_ZONE_DATA, slot, 0, 0, buf); err != nil {
		return
	}

	// Append first block to signature
	signature = append(signature, data...)

	// Read the second block
	if err = d.ReadZone(ATCA_ZONE_DATA, slot, 1, 0, buf); err != nil {
		return
	}

	// Append second block to signature
	signature = append(signature, data...)

	return
}
