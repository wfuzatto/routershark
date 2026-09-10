package capture

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"routershark/backend/internal/db"
	"routershark/backend/internal/model"
)

type Broadcast func(model.Packet)

type Collector struct {
	Addr          string
	Allowlist     []string
	Store         *db.Store
	BatchSize     int
	BatchInterval time.Duration
	Broadcast     Broadcast
}

func (c *Collector) allowed(ip string) bool {
	if len(c.Allowlist) == 0 {
		return true
	}
	for _, a := range c.Allowlist {
		if strings.TrimSpace(a) == ip {
			return true
		}
	}
	return false
}

func (c *Collector) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", c.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("TZSP collector listening on %s", c.Addr)
	ch := make(chan model.Packet, 10000)
	go c.writer(ctx, ch)
	buf := make([]byte, 65535)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-ctx.Done():
					return nil
				default:
					continue
				}
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		rip := remote.IP.String()
		if !c.allowed(rip) {
			continue
		}
		tz, err := DecodeTZSP(buf[:n])
		if err != nil {
			continue
		}
		p := model.Packet{ID: uuid.NewString(), ReceivedAt: time.Now().UTC(), RouterIP: rip, Encap: tz.Encap, Length: len(tz.Payload), Raw: tz.Payload}
		ParseFrame(tz.Payload, &p)
		if c.Broadcast != nil {
			c.Broadcast(p)
		}
		select {
		case ch <- p:
		default:
			log.Printf("packet queue full; dropping packet from %s", rip)
		}
	}
}

func (c *Collector) writer(ctx context.Context, ch <-chan model.Packet) {
	ticker := time.NewTicker(c.BatchInterval)
	defer ticker.Stop()
	batch := make([]model.Packet, 0, c.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		b := append([]model.Packet(nil), batch...)
		batch = batch[:0]
		if err := c.Store.InsertBatch(ctx, b); err != nil {
			log.Printf("db insert: %v", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case p := <-ch:
			batch = append(batch, p)
			if len(batch) >= c.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
