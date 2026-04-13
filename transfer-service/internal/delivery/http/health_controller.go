package http

import (
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type HealthController struct {
	Log *logrus.Logger
	DB  *gorm.DB
}

func NewHealthController(log *logrus.Logger, DB *gorm.DB) *HealthController {
	return &HealthController{Log: log, DB: DB}
}

func (r *HealthController) Health(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "UP",
		"service": "transfer-service",
	})
}

func (r *HealthController) DbConnection(c *fiber.Ctx) error {
	sqlDB, _ := r.DB.DB()
	if err := sqlDB.Ping(); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status": "DOWN",
			"db":     "unreachable",
		})
	}
	return c.JSON(fiber.Map{
		"status": "UP",
		"db":     "reachable",
	})
}
