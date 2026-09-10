package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"routershark/backend/internal/model"
)

type Store struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	p, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return &Store{Pool: p}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	ddl := `
CREATE TABLE IF NOT EXISTS packets (
 id uuid PRIMARY KEY,
 received_at timestamptz NOT NULL,
 router_ip inet NOT NULL,
 encap integer NOT NULL,
 src_mac text,
 dst_mac text,
 ethertype text,
 src_ip inet,
 dst_ip inet,
 ip_version smallint,
 protocol text,
 src_port integer,
 dst_port integer,
 length integer NOT NULL,
 info text,
 raw bytea NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_packets_time ON packets(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_packets_router_time ON packets(router_ip, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_packets_ports ON packets(src_port,dst_port);
`
	_, err := s.Pool.Exec(ctx, ddl)
	return err
}

func (s *Store) InsertBatch(ctx context.Context, items []model.Packet) error {
	return s.InsertBatch2(ctx, items)
}

type rowSource struct {
	rows [][]any
	idx  int
}

func (r *rowSource) Next() bool             { return r.idx < len(r.rows) }
func (r *rowSource) Values() ([]any, error) { v := r.rows[r.idx]; r.idx++; return v, nil }
func (r *rowSource) Err() error             { return nil }

func (s *Store) InsertBatch2(ctx context.Context, items []model.Packet) error {
	if len(items) == 0 {
		return nil
	}
	rows := make([][]any, 0, len(items))
	for _, p := range items {
		rows = append(rows, []any{p.ID, p.ReceivedAt, p.RouterIP, int(p.Encap), nulls(p.SrcMAC), nulls(p.DstMAC), nulls(p.EtherType), nulls(p.SrcIP), nulls(p.DstIP), nullableInt(p.IPVersion), nulls(p.Protocol), nullableInt(p.SrcPort), nullableInt(p.DstPort), p.Length, nulls(p.Info), p.Raw})
	}
	_, err := s.Pool.CopyFrom(ctx, pgx.Identifier{"packets"}, []string{"id", "received_at", "router_ip", "encap", "src_mac", "dst_mac", "ethertype", "src_ip", "dst_ip", "ip_version", "protocol", "src_port", "dst_port", "length", "info", "raw"}, &rowSource{rows: rows})
	return err
}

func nulls(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func nullableInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func (s *Store) ListPackets(ctx context.Context, q model.PacketQuery) ([]model.Packet, error) {
	if q.Limit <= 0 {
		q.Limit = 500
	}
	if q.Limit > 20000 {
		q.Limit = 20000
	}
	var where []string
	var args []any
	add := func(cond string, v any) { args = append(args, v); where = append(where, fmt.Sprintf(cond, len(args))) }
	if q.RouterIP != "" {
		add("router_ip = $%d::inet", q.RouterIP)
	}
	if q.SrcIP != "" {
		add("src_ip = $%d::inet", q.SrcIP)
	}
	if q.DstIP != "" {
		add("dst_ip = $%d::inet", q.DstIP)
	}
	if q.Protocol != "" {
		add("upper(protocol)=upper($%d)", q.Protocol)
	}
	if q.Port > 0 {
		args = append(args, q.Port)
		where = append(where, fmt.Sprintf("(src_port=$%d OR dst_port=$%d)", len(args), len(args)))
	}
	if q.Search != "" {
		args = append(args, q.Search)
		n := len(args)
		where = append(where, fmt.Sprintf("(info ILIKE '%%' || $%d || '%%' OR src_ip::text ILIKE '%%' || $%d || '%%' OR dst_ip::text ILIKE '%%' || $%d || '%%')", n, n, n))
	}
	if q.From != nil {
		add("received_at >= $%d", *q.From)
	}
	if q.To != nil {
		add("received_at <= $%d", *q.To)
	}
	sql := `SELECT id::text,received_at,router_ip::text,encap,coalesce(src_mac,''),coalesce(dst_mac,''),coalesce(ethertype,''),coalesce(src_ip::text,''),coalesce(dst_ip::text,''),coalesce(ip_version,0),coalesce(protocol,''),coalesce(src_port,0),coalesce(dst_port,0),length,coalesce(info,'') FROM packets`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	args = append(args, q.Limit, q.Offset)
	sql += fmt.Sprintf(" ORDER BY received_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := s.Pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Packet{}
	for rows.Next() {
		var p model.Packet
		if err := rows.Scan(&p.ID, &p.ReceivedAt, &p.RouterIP, &p.Encap, &p.SrcMAC, &p.DstMAC, &p.EtherType, &p.SrcIP, &p.DstIP, &p.IPVersion, &p.Protocol, &p.SrcPort, &p.DstPort, &p.Length, &p.Info); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetPacket(ctx context.Context, id string) (model.Packet, error) {
	var p model.Packet
	err := s.Pool.QueryRow(ctx, `SELECT id::text,received_at,router_ip::text,encap,coalesce(src_mac,''),coalesce(dst_mac,''),coalesce(ethertype,''),coalesce(src_ip::text,''),coalesce(dst_ip::text,''),coalesce(ip_version,0),coalesce(protocol,''),coalesce(src_port,0),coalesce(dst_port,0),length,coalesce(info,''),raw FROM packets WHERE id=$1`, id).Scan(&p.ID, &p.ReceivedAt, &p.RouterIP, &p.Encap, &p.SrcMAC, &p.DstMAC, &p.EtherType, &p.SrcIP, &p.DstIP, &p.IPVersion, &p.Protocol, &p.SrcPort, &p.DstPort, &p.Length, &p.Info, &p.Raw)
	return p, err
}

func (s *Store) StatsProtocols(ctx context.Context, since time.Time) ([]map[string]any, error) {
	rows, err := s.Pool.Query(ctx, `SELECT coalesce(protocol,'OTHER'),count(*),sum(length) FROM packets WHERE received_at >= $1 GROUP BY 1 ORDER BY 2 DESC LIMIT 30`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var proto string
		var count, bytes int64
		if err := rows.Scan(&proto, &count, &bytes); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"protocol": proto, "packets": count, "bytes": bytes})
	}
	return out, rows.Err()
}

func (s *Store) Range(ctx context.Context, from, to time.Time, limit int) ([]model.Packet, error) {
	return s.ListPackets(ctx, model.PacketQuery{From: &from, To: &to, Limit: limit})
}

func (s *Store) DeleteBefore(ctx context.Context, before time.Time) (int64, error) {
	tag, err := s.Pool.Exec(ctx, "DELETE FROM packets WHERE received_at < $1", before)
	return tag.RowsAffected(), err
}
