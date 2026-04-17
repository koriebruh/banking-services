package middleware

import (
	"strings"

	"github.com/google/uuid"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

func CorrelationID(log *logrus.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		correlationID := c.Get("X-Correlation-ID")

		// Fallback to query param, or generate a new one if missing
		if strings.TrimSpace(correlationID) == "" {
			correlationID = c.Query("correlation_id")
		}
		
		if strings.TrimSpace(correlationID) == "" {
			correlationID = uuid.New().String()
			log.WithFields(logrus.Fields{
				"method": c.Method(),
				"path":   c.Path(),
				"ip":     c.IP(),
			}).Warn("Missing X-Correlation-ID, auto-generated one: ", correlationID)
		}

		c.Set("X-Correlation-ID", correlationID)
		c.Locals("correlationId", correlationID)

		log.WithFields(logrus.Fields{
			"correlation_id": correlationID,
			"method":         c.Method(),
			"path":           c.Path(),
		}).Debug("Request correlation ID validated")

		return c.Next()
	}
}
