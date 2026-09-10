package capture

import "fmt"

type TZSPPacket struct {
	Version uint8
	Type    uint8
	Encap   uint16
	Payload []byte
}

func DecodeTZSP(b []byte) (TZSPPacket, error) {
	if len(b) < 5 {
		return TZSPPacket{}, fmt.Errorf("tzsp datagram too short")
	}
	p := TZSPPacket{Version: b[0], Type: b[1], Encap: uint16(b[2])<<8 | uint16(b[3])}
	if p.Version != 1 {
		return TZSPPacket{}, fmt.Errorf("unsupported tzsp version %d", p.Version)
	}
	i := 4
	for i < len(b) {
		tag := b[i]
		i++
		switch tag {
		case 0: // padding
			continue
		case 1: // end
			if i > len(b) {
				return TZSPPacket{}, fmt.Errorf("invalid tzsp end")
			}
			p.Payload = append([]byte(nil), b[i:]...)
			if len(p.Payload) == 0 {
				return TZSPPacket{}, fmt.Errorf("empty tzsp payload")
			}
			return p, nil
		default:
			if i >= len(b) {
				return TZSPPacket{}, fmt.Errorf("malformed tzsp tag")
			}
			l := int(b[i])
			i++
			if i+l > len(b) {
				return TZSPPacket{}, fmt.Errorf("truncated tzsp tag")
			}
			i += l
		}
	}
	return TZSPPacket{}, fmt.Errorf("tzsp end tag not found")
}
