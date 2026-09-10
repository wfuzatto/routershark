package model

import "time"

type Packet struct {
	ID         string    `json:"id"`
	ReceivedAt time.Time `json:"received_at"`
	RouterIP   string    `json:"router_ip"`
	Encap      uint16    `json:"encap"`
	SrcMAC     string    `json:"src_mac,omitempty"`
	DstMAC     string    `json:"dst_mac,omitempty"`
	EtherType  string    `json:"ethertype,omitempty"`
	SrcIP      string    `json:"src_ip,omitempty"`
	DstIP      string    `json:"dst_ip,omitempty"`
	IPVersion  int       `json:"ip_version,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	SrcPort    int       `json:"src_port,omitempty"`
	DstPort    int       `json:"dst_port,omitempty"`
	Length     int       `json:"length"`
	Info       string    `json:"info,omitempty"`
	Raw        []byte    `json:"-"`
}

type PacketQuery struct {
	RouterIP string
	SrcIP    string
	DstIP    string
	Protocol string
	Port     int
	Search   string
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}
