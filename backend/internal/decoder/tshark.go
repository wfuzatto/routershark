package decoder

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"routershark/backend/internal/model"
)

func PCAP(items []model.Packet) ([]byte, error) {
	var b bytes.Buffer
	// little endian PCAP, Ethernet linktype
	_ = binary.Write(&b, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(&b, binary.LittleEndian, uint16(2))
	_ = binary.Write(&b, binary.LittleEndian, uint16(4))
	_ = binary.Write(&b, binary.LittleEndian, int32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(0))
	_ = binary.Write(&b, binary.LittleEndian, uint32(65535))
	_ = binary.Write(&b, binary.LittleEndian, uint32(1))
	// chronological order for analysis/export
	for i := len(items) - 1; i >= 0; i-- {
		p := items[i]
		sec := uint32(p.ReceivedAt.Unix())
		usec := uint32(p.ReceivedAt.Nanosecond() / 1000)
		l := uint32(len(p.Raw))
		_ = binary.Write(&b, binary.LittleEndian, sec)
		_ = binary.Write(&b, binary.LittleEndian, usec)
		_ = binary.Write(&b, binary.LittleEndian, l)
		_ = binary.Write(&b, binary.LittleEndian, l)
		_, _ = b.Write(p.Raw)
	}
	return b.Bytes(), nil
}

func DecodePacket(ctx context.Context, p model.Packet) ([]byte, error) {
	data, _ := PCAP([]model.Packet{p})
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "tshark", "-r", "-", "-T", "json", "-x")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tshark: %w: %s", err, string(out))
	}
	return out, nil
}

func FilterFrameNumbers(ctx context.Context, items []model.Packet, filter string) ([]int, error) {
	data, _ := PCAP(items)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "tshark", "-r", "-", "-Y", filter, "-T", "fields", "-e", "frame.number")
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("invalid/failed display filter: %w: %s", err, string(out))
	}
	var nums []int
	for _, field := range strings.Fields(string(out)) {
		n, err := strconv.Atoi(field)
		if err == nil && n > 0 {
			nums = append(nums, n)
		}
	}
	return nums, nil
}

func Follow(ctx context.Context, items []model.Packet, proto, mode, stream string) ([]byte, error) {
	data, _ := PCAP(items)
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	z := fmt.Sprintf("follow,%s,%s,%s", proto, mode, stream)
	cmd := exec.CommandContext(cctx, "tshark", "-r", "-", "-q", "-z", z)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tshark follow: %w: %s", err, string(out))
	}
	return out, nil
}
