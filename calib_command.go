package cryptoauthlib

import (
	"time"
	"unsafe"
)

type packet struct {
	buf []byte
}

func newReadCommand(buf []byte) *packet {
	p := &packet{
		buf: buf,
	}

	p.setOpcode(ATCA_READ)
	p.setCount(uint8(ATCA_CMD_SIZE_MIN))

	return p
}

func newSHACommand(buf []byte, mode uint8, length uint16) *packet {
	p := &packet{
		buf: buf,
	}

	p.setOpcode(ATCA_SHA)
	p.setParam1(mode)
	p.setParam2(length)

	switch mode & SHA_MODE_MASK {
	case SHA_MODE_SHA256_START, SHA_MODE_HMAC_START, 0x03:
		p.setCount(uint8(ATCA_CMD_SIZE_MIN))
	case SHA_MODE_SHA256_UPDATE:
		p.setCount(uint8(ATCA_CMD_SIZE_MIN + int(length)))
	case SHA_MODE_SHA256_END, SHA_MODE_HMAC_END:
		p.setCount(uint8(ATCA_CMD_SIZE_MIN + int(length)))
	case SHA_MODE_READ_CONTEXT:
		p.setCount(uint8(ATCA_CMD_SIZE_MIN))
	case SHA_MODE_WRITE_CONTEXT:
		p.setCount(uint8(ATCA_CMD_SIZE_MIN + int(length)))
	}

	return p
}

func newGenKeyCommand(buf []byte, mode uint8, keyId uint16) *packet {
	p := &packet{buf: buf}

	p.setOpcode(ATCA_GENKEY)
	p.setParam1(mode)
	p.setParam2(keyId)

	if mode&GENKEY_MODE_PUBKEY_DIGEST != 0 {
		p.setCount(uint8(GENKEY_COUNT_DATA))
	} else {
		p.setCount(uint8(GENKEY_COUNT))
	}

	return p
}

func newNonceCommand(buf []byte, mode uint8, zero uint16) *packet {
	p := &packet{buf: buf}
	p.setOpcode(ATCA_NONCE)
	p.setParam1(mode)
	p.setParam2(zero)

	switch mode & NONCE_MODE_MASK {
	case NONCE_MODE_SEED_UPDATE, NONCE_MODE_NO_SEED_UPDATE:
		p.setCount(uint8(NONCE_COUNT_SHORT))
	case NONCE_MODE_PASSTHROUGH:
		if mode&NONCE_MODE_INPUT_LEN_MASK == NONCE_MODE_INPUT_LEN_64 {
			p.setCount(uint8(NONCE_COUNT_LONG_64))
		} else {
			p.setCount(uint8(NONCE_COUNT_LONG))
		}
	}

	return p
}

func newSignCommand(buf []byte, mode uint8, keyId uint16) *packet {
	p := &packet{buf: buf}
	p.setOpcode(ATCA_SIGN)
	p.setParam1(mode)
	p.setParam2(keyId)
	p.setCount(uint8(SIGN_COUNT))

	return p
}

func newRandomCommand(buf []byte) *packet {
	p := &packet{buf: buf}
	p.setOpcode(ATCA_RANDOM)
	p.setCount(uint8(RANDOM_COUNT))

	return p
}

func (p *packet) count() uint8 {
	return p.buf[ATCA_COUNT_IDX]
}

func (p *packet) setCount(count uint8) {
	p.buf[ATCA_COUNT_IDX] = count
}

func (p *packet) opcode() byte {
	return p.buf[ATCA_OPCODE_IDX]
}

func (p *packet) setOpcode(opcode byte) {
	p.buf[ATCA_OPCODE_IDX] = opcode
}

func (p *packet) setParam1(val byte) {
	p.buf[ATCA_PARAM1_IDX] = val
}

func (p *packet) setParam2(val uint16) {
	p.buf[ATCA_PARAM2_IDX] = byte(val)
	p.buf[ATCA_PARAM2_IDX+1] = byte(val >> 8)
}

func (p *packet) data() []byte {
	return p.buf[ATCA_DATA_IDX:]
}

//go:noinline
func (p *packet) execute(t Transport) (err error) {
	// Calculate length of the command packet
	cmdEndPos := int(p.count()) - ATCA_CRC_SIZE

	// Calculate the CRC of the command packet to be sent and store it in the last 2 bytes
	crc16(p.buf[:cmdEndPos], p.buf[cmdEndPos:cmdEndPos+2])

	// Set the register based on the mode of transport
	var wordAddress byte
	switch t.(type) {
	case *i2cTransport:
		wordAddress = 0x03
	}

	// TODO: Begin retry loop
	// Wake up the device
	t.WakeUp()

	// Send the command packet
	if err = t.Send(wordAddress, p.buf[:p.count()]); err != nil {
		return err
	}

	//TODO: End retry loop

	// TODO: Begin retry loop
	// Zero-out the data buffer
	for i := range p.buf {
		p.buf[i] = 0
	}

	// The result is likely to NOT be ready to receive right away. Delay for some time
	time.Sleep(time.Millisecond * 10)

	// Send word address until the device responds with an ack or the deadline is exceeded
	// TODO: The word address is non-zero for SWI transport
	wordAddress = 0

	deadline := time.Now().Add(time.Millisecond * 500)
	for {
		if time.Now().Before(deadline) {
			if err = t.Send(wordAddress, nil); err != nil {
				time.Sleep(time.Millisecond * 10)
				continue
			}
			break
		} else {
			// Return the error
			return
		}
	}

	// Receive response length from device
	var responseLength uint8
	if err = t.Receive(wordAddress, unsafe.Slice(&responseLength, 1)); err != nil {
		return
	}

	// Receive the response
	if err = t.Receive(wordAddress, p.buf[:responseLength]); err != nil {
		return err
	}

	// Check crc
	var crc [2]byte
	dataCrc := p.buf[responseLength-2:]
	crc16(p.buf[:int(responseLength)-ATCA_CRC_SIZE], crc[:])

	if dataCrc[0] != crc[0] || dataCrc[1] != crc[1] {
		return StatusRxCrcError
	}

	// Check for error
	if p.buf[0] == 0x04 {
		if err = mapCommandStatus(p.buf[1]); err != StatusSuccess {
			return
		}
	}

	//TODO: End retry loop

	return nil
}
