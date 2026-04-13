package route

import (
	"golang-clean-architecture/internal/delivery/http"
	"golang-clean-architecture/internal/telemetry"

	"github.com/gofiber/contrib/otelfiber"
	"github.com/gofiber/fiber/v2"
)

type RouteConfig struct {
	App                     *fiber.App
	TransferController      *http.TransferController
	HealthController        *http.HealthController
	CorrelationIdMiddleware fiber.Handler
	JwtMiddleware           fiber.Handler
	Telemetry               *telemetry.Providers
}

func (c *RouteConfig) Setup() {
	c.SetupRoute()
}

func (c *RouteConfig) SetupRoute() {
	// OPEN TELEMETRY
	c.App.Use(otelfiber.Middleware())

	// HEALTH CHECK
	c.App.Get("/health", c.HealthController.Health)
	c.App.Get("/health/ready", c.HealthController.DbConnection)

	// CONNECT WITH MIDDLEWARE
	c.App.Use(c.CorrelationIdMiddleware)
	v1 := c.App.Group("/api/v1")

	// LIST OF ROUTE --
	transfers := v1.Group("/transfers", c.JwtMiddleware)
	transfers.Post("/topup", c.TransferController.TopUp)
	transfers.Post("/", c.TransferController.Initiate)
	transfers.Post("/:referenceId/confirm", c.TransferController.Confirm)
	transfers.Post("/:referenceId/cancel", c.TransferController.Cancel)
	transfers.Get("/", c.TransferController.GetMyTransfers)
	transfers.Get("/:referenceId", c.TransferController.GetDetail)
	transfers.Get("/accounts/:accountNumber/history", c.TransferController.GetAccountHistory)

}
