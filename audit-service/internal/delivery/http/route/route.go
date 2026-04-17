package route

import (
	"golang-clean-architecture/internal/delivery/http"
	"golang-clean-architecture/internal/telemetry"

	"github.com/gofiber/fiber/v2"
)

type RouteConfig struct {
	App                     *fiber.App
	AuditController         *http.AuditController
	CorrelationIdMiddleware fiber.Handler
	JwtMiddleware           fiber.Handler
	Telemetry               *telemetry.Providers
}

func (c *RouteConfig) Setup() {
	c.SetupRoute()
}

func (c *RouteConfig) SetupRoute() {
	// HEALTH CHECK
	c.App.Get("/health", func(ctx *fiber.Ctx) error {
		return ctx.SendStatus(fiber.StatusOK)
	})

	// MIDDLEWARE
	c.App.Use(c.CorrelationIdMiddleware)

	// AUDIT LOG API — Protected with JWT
	api := c.App.Group("/api", c.JwtMiddleware)
	api.Get("/audit-logs", c.AuditController.FindAll)
}
