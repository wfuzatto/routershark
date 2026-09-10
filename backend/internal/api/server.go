package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"routershark/backend/internal/db"
	"routershark/backend/internal/decoder"
	"routershark/backend/internal/model"
)

type Server struct {
	Store   *db.Store
	Token   string
	clients map[*websocket.Conn]bool
	mu      sync.Mutex
}

func New(store *db.Store, token string) *Server {
	return &Server{Store: store, Token: token, clients: map[*websocket.Conn]bool{}}
}

func (s *Server) Broadcast(p model.Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		_ = c.WriteJSON(p)
	}
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/api/health", s.health)
	m.HandleFunc("/api/packets", s.packets)
	m.HandleFunc("/api/packets/", s.packet)
	m.HandleFunc("/api/stats/protocols", s.statsProtocols)
	m.HandleFunc("/api/display-filter", s.displayFilter)
	m.HandleFunc("/api/follow", s.follow)
	m.HandleFunc("/api/export.pcap", s.exportPCAP)
	m.HandleFunc("/ws/packets", s.ws)
	return s.auth(cors(m))
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/health") || s.Token == "" {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			token = r.URL.Query().Get("token")
		}
		if token != s.Token {
			http.Error(w, "unauthorized", 401)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"ok": true, "time": time.Now().UTC()})
}

func parseTime(v string) (*time.Time, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	return &t, err
}
func (s *Server) packets(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	limit, _ := strconv.Atoi(qv.Get("limit"))
	offset, _ := strconv.Atoi(qv.Get("offset"))
	port, _ := strconv.Atoi(qv.Get("port"))
	from, _ := parseTime(qv.Get("from"))
	to, _ := parseTime(qv.Get("to"))
	items, err := s.Store.ListPackets(r.Context(), model.PacketQuery{RouterIP: qv.Get("router_ip"), SrcIP: qv.Get("src_ip"), DstIP: qv.Get("dst_ip"), Protocol: qv.Get("protocol"), Port: port, Search: qv.Get("q"), From: from, To: to, Limit: limit, Offset: offset})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, items)
}
func (s *Server) packet(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/packets/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	p, err := s.Store.GetPacket(r.Context(), parts[0])
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	if len(parts) == 1 {
		p.Raw = nil
		writeJSON(w, p)
		return
	}
	switch parts[1] {
	case "decode":
		out, err := decoder.DecodePacket(r.Context(), p)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	case "hex":
		writeJSON(w, map[string]any{"id": p.ID, "hex": hex.Dump(p.Raw)})
	case "raw":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(p.Raw)
	default:
		http.NotFound(w, r)
	}
}
func (s *Server) statsProtocols(w http.ResponseWriter, r *http.Request) {
	mins, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if mins <= 0 {
		mins = 60
	}
	data, err := s.Store.StatsProtocols(r.Context(), time.Now().UTC().Add(-time.Duration(mins)*time.Minute))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, data)
}
func rangeParams(r *http.Request) (time.Time, time.Time, int, error) {
	q := r.URL.Query()
	to := time.Now().UTC()
	from := to.Add(-5 * time.Minute)
	var err error
	if q.Get("from") != "" {
		from, err = time.Parse(time.RFC3339, q.Get("from"))
		if err != nil {
			return from, to, 0, err
		}
	}
	if q.Get("to") != "" {
		to, err = time.Parse(time.RFC3339, q.Get("to"))
		if err != nil {
			return from, to, 0, err
		}
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 20000 {
		limit = 10000
	}
	return from, to, limit, nil
}
func (s *Server) displayFilter(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		http.Error(w, "filter required", 400)
		return
	}
	from, to, limit, err := rangeParams(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	items, err := s.Store.Range(r.Context(), from, to, limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	frames, err := decoder.FilterFrameNumbers(r.Context(), items, filter)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	// PCAP() writes items in reverse order (oldest first), therefore frame 1 maps to items[len-1].
	matches := make([]model.Packet, 0, len(frames))
	for _, frame := range frames {
		idx := len(items) - frame
		if idx >= 0 && idx < len(items) {
			matches = append(matches, items[idx])
		}
	}
	writeJSON(w, map[string]any{"frame_numbers": frames, "range_packets": len(items), "packets": matches})
}
func (s *Server) follow(w http.ResponseWriter, r *http.Request) {
	proto := r.URL.Query().Get("proto")
	if proto == "" {
		proto = "tcp"
	}
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "utf-8"
	}
	stream := r.URL.Query().Get("stream")
	if stream == "" {
		http.Error(w, "stream required", 400)
		return
	}
	from, to, limit, err := rangeParams(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	items, err := s.Store.Range(r.Context(), from, to, limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out, err := decoder.Follow(r.Context(), items, proto, mode, stream)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(out)
}
func (s *Server) exportPCAP(w http.ResponseWriter, r *http.Request) {
	from, to, limit, err := rangeParams(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	items, err := s.Store.Range(r.Context(), from, to, limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	data, _ := decoder.PCAP(items)
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=routershark-%s.pcap", time.Now().UTC().Format("20060102-150405")))
	_, _ = w.Write(data)
}
func (s *Server) ws(w http.ResponseWriter, r *http.Request) {
	up := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	c, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.clients[c] = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.clients, c); s.mu.Unlock(); _ = c.Close() }()
	for {
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
	}
}

var _ = context.Background
