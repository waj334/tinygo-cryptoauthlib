package cryptoauthlib

func PrintBytes(s []byte) {
	printBytes(s)
}

func printBytes(s []byte) {
	for _, b := range s {
		PrintByte(b)
		print(" ")
	}

	print("\n\r")
}

func printBytesL(s []byte) {
	for _, b := range s {
		PrintByte(b)
		print(" ")
	}
}

func PrintByte(b byte) {
	upper := (b >> 4) & 0x0F
	lower := b & 0x0F

	print(hex(upper))
	print(hex(lower))
}

func hex(b byte) string {
	switch b {
	case 0:
		return "0"
	case 1:
		return "1"
	case 2:
		return "2"
	case 3:
		return "3"
	case 4:
		return "4"
	case 5:
		return "5"
	case 6:
		return "6"
	case 7:
		return "7"
	case 8:
		return "8"
	case 9:
		return "9"
	case 10:
		return "A"
	case 11:
		return "B"
	case 12:
		return "C"
	case 13:
		return "D"
	case 14:
		return "E"
	case 15:
		return "F"
	default:
		return "NOP"
	}
}
