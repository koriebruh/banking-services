package config

import (
	"context"

	"golang-clean-architecture/internal/delivery/http"
	"golang-clean-architecture/internal/delivery/http/middleware"
	"golang-clean-architecture/internal/delivery/http/route"
	"golang-clean-architecture/internal/repository"
	"golang-clean-architecture/internal/telemetry"
	"golang-clean-architecture/internal/usecase"
	"golang-clean-architecture/internal/worker"

	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type BootstrapConfig struct {
	App       *fiber.App
	Log       *logrus.Logger
	Config    *viper.Viper
	Telemetry *telemetry.Providers
}

func Bootstrap(cfg *BootstrapConfig) {
	// LOAD PUBLIC KEY FOR JWT
	if err := middleware.LoadPublicKey(cfg.Config, cfg.Log); err != nil {
		cfg.Log.Fatalf("Failed to load JWT public key: %v", err)
	}

	// DATABASE
	db := NewDatabase(cfg.Config, cfg.Log)

	// REPOSITORY
	auditRepo := repository.NewAuditRepository(db, cfg.Log)

	// USECASE
	auditUsecase := usecase.NewAuditUsecase(cfg.Log, auditRepo)

	// CONTROLLER
	auditController := http.NewAuditController(cfg.Log, auditUsecase)

	// MIDDLEWARE
	correlationIdMiddleware := middleware.CorrelationID(cfg.Log)
	jwtMiddleware := middleware.JWTProtected(cfg.Log)

	// ROUTES
	routeConfig := route.RouteConfig{
		App:                     cfg.App,
		AuditController:         auditController,
		CorrelationIdMiddleware: correlationIdMiddleware,
		JwtMiddleware:           jwtMiddleware,
		Telemetry:               cfg.Telemetry,
	}
	routeConfig.Setup()

	// AUDIT WORKER (Kafka Consumer → Usecase → DB)
	auditWorker := worker.NewAuditWorker(cfg.Log, cfg.Config, auditUsecase)
	auditWorker.Start(context.Background())
}
