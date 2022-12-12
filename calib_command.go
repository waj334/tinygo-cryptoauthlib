package cryptoauthlib

import (
	"time"
)

type packet struct {
	buf              []byte
	inputDataLength  int
	outputDataLength int
}

func newReadCommand(buf []byte) *packet {
	p := &packet{
		buf:              buf,
		inputDataLength:  0,
		outputDataLength: 32,
	}

	p.setOpcode(ATCA_READ)
	p.setCount(uint8(ATCA_CMD_SIZE_MIN + p.inputDataLength))

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

//go:noinline
func (p *packet) execute(t Transport) (err error) {
	// Calculate length of the command packet
	cmdEndPos := int(p.count()) - ATCA_CRC_SIZE
	println("cmdEndPos =", cmdEndPos)

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
	if err = t.WakeUp(); err != nil {
		return
	}

	// Send the command packet
	if err = t.Send(wordAddress, p.buf[:p.count()]); err != nil {
		return err
	}

	//TODO: End retry loop

	// Delay
	time.Sleep(time.Millisecond * 10)

	// TODO: Begin retry loop
	// Zero-out the data buffer
	for i := range p.buf {
		p.buf[i] = 0
	}

	// Send word address
	// TODO: The word address is non-zero for SWI transport
	wordAddress = 0
	if err = t.Send(wordAddress, nil); err != nil {
		return
	}

	// Receive response length from device
	var tmp [1]uint8
	if err = t.Receive(wordAddress, tmp[:]); err != nil {
		return
	}

	responseLength := int(tmp[0])

	// Receive the response
	if err = t.Receive(wordAddress, p.buf[:responseLength]); err != nil {
		return err
	}

	// Check crc
	var crc [2]byte
	dataCrc := p.buf[responseLength-2:]
	crc16(p.buf[:responseLength-ATCA_CRC_SIZE], crc[:])

	if dataCrc[0] != crc[0] || dataCrc[1] != crc[1] {
		return StatusRxCrcError
	}

	// Check for error
	if p.buf[0] == 0x04 {
		return mapCommandStatus(p.buf[1])
	}

	//TODO: End retry loop

	return nil
}
