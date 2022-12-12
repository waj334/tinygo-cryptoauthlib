package cryptoauthlib

const polynom uint16 = 0x8005

func crc16(data []byte, out []byte) {
	var crcRegister uint16
	var dataBit, crcBit uint8

	for counter := 0; counter < len(data); counter++ {
		for shiftRegister := byte(0x01); shiftRegister > 0x00; shiftRegister <<= 1 {
			dataBit = 0
			if data[counter]&shiftRegister != 0 {
				dataBit = 1
			}

			crcBit = uint8(crcRegister >> 15)
			crcRegister <<= 1

			if dataBit != crcBit {
				crcRegister ^= polynom
			}
		}
	}

	out[0] = byte(crcRegister & 0x00FF)
	out[1] = byte(crcRegister >> 8)
}
