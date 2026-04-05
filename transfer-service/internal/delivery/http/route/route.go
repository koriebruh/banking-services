package route

import (
	"golang-clean-architecture/internal/delivery/http"

	"github.com/gofiber/fiber/v2"
)

type RouteConfig struct {
	App                     *fiber.App
	TransferController      *http.TransferController
	CorrelationIdMiddleware fiber.Handler
	JwtMiddleware           fiber.Handler
}

func (c *RouteConfig) Setup() {
	c.SetupRoute()
}

func (c *RouteConfig) SetupRoute() {
	// CONNECT WITH MIDDLEWARE
	c.App.Use(c.CorrelationIdMiddleware)
	c.App.Use(c.JwtMiddleware)
	v1 := c.App.Group("/api/v1")

	// LIST OF ROUTE --
	transfers := v1.Group("/transfers", c.JwtMiddleware)
	transfers.Post("/", c.TransferController.Initiate)
	transfers.Post("/:referenceId/confirm", c.TransferController.Confirm)
	transfers.Post("/:referenceId/cancel", c.TransferController.Cancel)
	transfers.Get("/", c.TransferController.GetMyTransfers)
	transfers.Get("/:referenceId", c.TransferController.GetDetail)
	transfers.Get("/accounts/:accountNumber/history", c.TransferController.GetAccountHistory)

}
