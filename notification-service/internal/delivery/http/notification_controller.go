package http

import (
	"log"

	"golang-clean-architecture/internal/hub"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type NotificationController struct {
	Log *logrus.Logger
	Hub *hub.Hub
}

func NewNotificationController(log *logrus.Logger, h *hub.Hub) *NotificationController {
	return &NotificationController{
		Log: log,
		Hub: h,
	}
}

// Ensure WebSockets Middleware Upgrade
func (ctr *NotificationController) Upgrade() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) {
			c.Locals("allowed", true)
			return c.Next()
		}
		return fiber.ErrUpgradeRequired
	}
}

func (ctr *NotificationController) HandleWebSocket() fiber.Handler {
	return websocket.New(func(c *websocket.Conn) {
		userCode, ok := c.Locals("userCode").(string)
		if !ok || userCode == "" {
			ctr.Log.Warn("[ws] userCode not found in locals or empty")
			return
		}
		userID := userCode // Use userCode for the hub registration

		ctr.Hub.Register(userID, c)
		defer ctr.Hub.Unregister(userID, c)

		// Send initial ACK
		if err := c.WriteJSON(fiber.Map{
			"type": "CONNECTED",
			"message": "WebSocket connected successfully",
		}); err != nil {
			ctr.Log.Errorf("[ws] failed to send ACK to %s: %v", userID, err)
			return
		}

		// Read loop to keep the connection alive and handle disconnects
		var (
			msgType int
			msg     []byte
			err     error
		)
		for {
			if msgType, msg, err = c.ReadMessage(); err != nil {
				log.Printf("[ws] read error %s: %v", userID, err)
				break
			}
			log.Printf("[ws] received message from %s (type %d): %s", userID, msgType, string(msg))
		}
	})
}
