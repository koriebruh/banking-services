package route

import (
	"golang-clean-architecture/internal/delivery/http"

	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/gofiber/fiber/v2"
)

type RouteConfig struct {
	App                     *fiber.App
	TransferController      *http.TransferController
	HealthController        *http.HealthController
	CorrelationIdMiddleware fiber.Handler
	JwtMiddleware           fiber.Handler
	PrometheusMiddleware    *fiberprometheus.FiberPrometheus
}

func (c *RouteConfig) Setup() {
	c.SetupRoute()
}

func (c *RouteConfig) SetupRoute() {
	c.App.Get("/health", c.HealthController.Health)
	c.App.Get("/health/ready", c.HealthController.DbConnection)

	// MATRIC MIDDLEWARE
	c.App.Use(c.PrometheusMiddleware.Middleware)
	c.PrometheusMiddleware.RegisterAt(c.App, "/metrics")

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
