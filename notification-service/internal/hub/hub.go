package hub

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/gofiber/contrib/websocket"
)

type connSet map[*websocket.Conn]struct{}

type Hub struct {
	mu    sync.RWMutex
	conns map[string]connSet // userId → set of conns
}

func New() *Hub {
	return &Hub{
		conns: make(map[string]connSet),
	}
}

// Register adds a connection for the given userId.
func (h *Hub) Register(userID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, ok := h.conns[userID]; !ok {
		h.conns[userID] = make(connSet)
	}
	h.conns[userID][conn] = struct{}{}

	log.Printf("[hub] registered userID=%s total_users=%d", userID, len(h.conns))
}

// Unregister removes a specific connection. Cleans up the user entry if no conns remain.
func (h *Hub) Unregister(userID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if set, ok := h.conns[userID]; ok {
		delete(set, conn)
		if len(set) == 0 {
			delete(h.conns, userID)
		}
	}

	log.Printf("[hub] unregistered userID=%s total_users=%d", userID, len(h.conns))
}

// SendToUser serialises v as JSON and writes it to all connections of the given user.
// Broken connections are silently cleaned up.
func (h *Hub) SendToUser(userID string, v any) {
	payload, err := json.Marshal(v)
	if err != nil {
		log.Printf("[hub] marshal error: %v", err)
		return
	}

	h.mu.RLock()
	set, ok := h.conns[userID]
	if !ok {
		h.mu.RUnlock()
		return
	}
	// Snapshot so we don't hold the lock during writes.
	conns := make([]*websocket.Conn, 0, len(set))
	for c := range set {
		conns = append(conns, c)
	}
	h.mu.RUnlock()

	for _, c := range conns {
		if err := c.WriteMessage(1 /* TextMessage */, payload); err != nil {
			log.Printf("[hub] write error userID=%s: %v — removing conn", userID, err)
			h.Unregister(userID, c)
		}
	}
}

// ActiveUsers returns the count of users with at least one open connection.
func (h *Hub) ActiveUsers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}
