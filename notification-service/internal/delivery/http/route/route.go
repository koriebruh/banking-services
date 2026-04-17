package route

import (
	"golang-clean-architecture/internal/delivery/http"
	"golang-clean-architecture/internal/telemetry"

	"github.com/gofiber/fiber/v2"
)

type RouteConfig struct {
	App                     *fiber.App
	NotificationController  *http.NotificationController
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



	// CONNECT WITH MIDDLEWARE
	c.App.Use(c.CorrelationIdMiddleware)

	// WEBSOCKET ROUTE
	c.App.Get("/ws/notifications", c.JwtMiddleware, c.NotificationController.Upgrade(), c.NotificationController.HandleWebSocket())
}
