package cryptoauthlib

type IOMode uint8

const (
	ReadBlock IOMode = ATCA_BLOCK_SIZE
	ReadWord  IOMode = ATCA_WORD_SIZE
)

func (d *Device) ReadZone(zone uint8, slot uint16, blockNo uint8, offset uint8, mode IOMode) (data []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	var address uint16

	// The input slice must NOT be nil and MUST be exactly 4 OR 32 bytes long
	switch mode {
	case ReadBlock:
		zone |= ATCA_ZONE_READWRITE_32
	case ReadWord:
	// Do nothing
	default:
		return nil, StatusBadParam
	}

	// The get address function checks the remaining variables
	if address, err = getAddress(zone, slot, blockNo, offset); err != nil {
		return
	}

	// Build a read command packet
	buf := make([]byte, ATCA_BLOCK_SIZE+ATCA_CMD_SIZE_MIN)
	packet := newReadCommand(buf)
	packet.setParam1(zone)
	packet.setParam2(address)

	// Execute the command
	if err = packet.execute(d.transport); err != nil {
		return
	}

	// Drop status byte
	return buf[1:], nil
}

func (d *Device) ReadBytesZone(zone uint8, slot uint16, offset int, data []byte) (err error) {
	length := len(data)
	if zone != ATCA_ZONE_CONFIG && zone != ATCA_ZONE_OTP && zone != ATCA_ZONE_DATA {
		return StatusBadParam
	} else if zone == ATCA_ZONE_DATA && slot > 15 {
		return StatusBadParam
	} else if length == 0 {
		return StatusBadParam
	}

	currentBlock := offset / ATCA_BLOCK_SIZE
	currentOffset := 0
	readMode := ReadBlock
	index := 0

	var _zoneSize int
	if _zoneSize, err = zoneSize(zone, slot); err != nil {
		return err
	}

	for index < length {
		var buf []byte

		if readMode == ReadBlock && _zoneSize-currentBlock*ATCA_BLOCK_SIZE < ATCA_BLOCK_SIZE {
			// We have less than a block to read and can't read past the end of the zone, switch to word reads
			readMode = ReadWord
			currentOffset = ((index + offset) / ATCA_WORD_SIZE) % (ATCA_BLOCK_SIZE / ATCA_WORD_SIZE)
		}

		// Read next chunk of data
		if buf, err = d.ReadZone(zone, slot, uint8(currentBlock), uint8(currentOffset), readMode); err != nil {
			return err
		}

		// Calculate where in the read buffer we need data from
		readOffset := currentBlock*ATCA_BLOCK_SIZE + currentOffset*ATCA_WORD_SIZE
		readIndex := 0
		if readOffset < offset {
			readIndex = offset - readOffset
		}

		// Calculate how much data from the read buffer we want to copy
		copyLength := int(readMode) - readIndex
		if length-index < int(readMode)-readIndex {
			copyLength = length - index
		}

		copy(data[index:], buf[readIndex:readIndex+copyLength])
		index += copyLength

		if readMode == ReadBlock {
			currentBlock++
		} else {
			currentOffset++
		}
	}

	return
}

func (d *Device) ReadConfigZone() (data []byte, err error) {
	// TODO: Consider devices other than ATECCx08?
	data = make([]byte, ATCA_ECC_CONFIG_SIZE)
	if err = d.ReadBytesZone(ATCA_ZONE_CONFIG, 0, 0, data); err != nil {
		return nil, err
	}
	return
}

func (d *Device) ReadEncrypted(keyId uint16, block uint8, encKey []byte, encKeyId uint16, num []byte) (data []byte, err error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	const zone = ATCA_ZONE_DATA | ATCA_ZONE_READWRITE_32
	var sn [9]byte
	var rand []byte
	tempKey := &tempKey{}

	if len(encKey) == 0 {
		return nil, StatusBadParam
	}

	// Read the device's serial number
	if sn, err = d.ReadSerialNumber(); err != nil {
		return nil, err
	}

	// Send the random nonce command
	if rand, err = d.NonceRand(num); err != nil {
		return nil, err
	}

	// Calculate the temporary key
	rand, tempKey, err = swNonce(NONCE_MODE_SEED_UPDATE, 0, num, rand, tempKey)

	// Send the gendig command
	var otherData [4]byte
	otherData[0] = ATCA_GENDIG
	otherData[1] = GENDIG_ZONE_DATA
	otherData[2] = uint8(encKeyId)
	otherData[3] = uint8(encKeyId >> 8)

	if err = d.GenDig(GENDIG_ZONE_DATA, keyId, otherData[:]); err != nil {
		return
	}

	// Calculate temp key
	gdParams := genDigParams{
		keyId:     encKeyId,
		noMac:     false,
		sn:        sn,
		value:     encKey,
		zone:      GENDIG_ZONE_DATA,
		otherData: otherData[:],
		tempKey:   tempKey,
	}

	if err = swGenDig(&gdParams); err != nil {
		return
	}

	// Read encrypted
	if data, err = d.ReadZone(zone, keyId, block, 0, ReadBlock); err != nil {
		return
	}

	// Decrypt
	for i := range data {
		data[i] = data[i] ^ tempKey.value[i]
	}

	return
}

func (d *Device) ReadPublicKey(slot uint16) (pubkey []byte, err error) {
	// Check the value of the slot
	if slot < 8 || slot > 0xF {
		return nil, StatusBadParam
	}

	var data []byte
	pubkey = make([]byte, 0, ATCA_PUB_KEY_SIZE)

	// The 64 byte P256 public key gets written to a 72 byte slot in the following pattern
	// | Block 1                     | Block 2                                      | Block 3       |
	// | Pad: 4 Bytes | PubKey[0:27] | PubKey[28:31] | Pad: 4 Bytes | PubKey[32:55] | PubKey[56:63] |
	// Read the first block
	if data, err = d.ReadZone(ATCA_ZONE_DATA, slot, 0, 0, ReadBlock); err != nil {
		return nil, err
	}

	// Append to public key skipping padding
	pubkey = append(pubkey, data[4:]...)

	// Read the next block
	if data, err = d.ReadZone(ATCA_ZONE_DATA, slot, 1, 0, ReadBlock); err != nil {
		return
	}

	// Append to public key skipping padding
	pubkey = append(pubkey, data[:4]...)
	pubkey = append(pubkey, data[8:]...)

	// Read the final block
	if data, err = d.ReadZone(ATCA_ZONE_DATA, slot, 2, 0, ReadBlock); err != nil {
		return
	}

	// Append to public key
	pubkey = append(pubkey, data[:8]...)

	return
}

func (d *Device) ReadSerialNumber() (result [9]byte, err error) {
	var buf []byte
	if buf, err = d.ReadZone(ATCA_ZONE_CONFIG, 0, 0, 0, ReadBlock); err != nil {
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

	var data []byte

	// Read the first block
	if data, err = d.ReadZone(ATCA_ZONE_DATA, slot, 0, 0, ReadBlock); err != nil {
		return
	}

	// Append first block to signature
	signature = append(signature, data...)

	// Read the second block
	if data, err = d.ReadZone(ATCA_ZONE_DATA, slot, 1, 0, ReadBlock); err != nil {
		return
	}

	// Append second block to signature
	signature = append(signature, data...)

	return
}
