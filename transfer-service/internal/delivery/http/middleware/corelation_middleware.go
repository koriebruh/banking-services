package middleware

import (
	"golang-clean-architecture/internal/shared/response"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

func CorrelationID(log *logrus.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		correlationID := c.Get("X-Correlation-ID")

		if strings.TrimSpace(correlationID) == "" {
			log.WithFields(logrus.Fields{
				"method": c.Method(),
				"path":   c.Path(),
				"ip":     c.IP(),
			}).Warn("Missing X-Correlation-ID header in request")

			return c.Status(fiber.StatusBadRequest).JSON(
				response.Error("Missing required header: X-Correlation-ID", ""),
			)
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
