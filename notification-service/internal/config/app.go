package config

import (
	"context"

	"golang-clean-architecture/internal/delivery/http"
	"golang-clean-architecture/internal/delivery/http/middleware"
	"golang-clean-architecture/internal/delivery/http/route"
	"golang-clean-architecture/internal/hub"
	"golang-clean-architecture/internal/telemetry"
	"golang-clean-architecture/internal/worker"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type BootstrapConfig struct {
	App           *fiber.App
	Log           *logrus.Logger
	Config        *viper.Viper
	Telemetry     *telemetry.Providers
}

func Bootstrap(cfg *BootstrapConfig) {
	// LOAD PUBLIC KEY FOR JWT
	if err := middleware.LoadPublicKey(cfg.Config, cfg.Log); err != nil {
		cfg.Log.Fatalf("Failed to load JWT public key: %v", err)
	}


	// HUB & WS
	notificationHub := hub.New()
	notificationController := http.NewNotificationController(cfg.Log, notificationHub)

	// MIDDLEWARE
	correlationIdMiddleware := middleware.CorrelationID(cfg.Log)
	jwtMiddleware := middleware.JWTProtected(cfg.Log)

	//
	routeConfig := route.RouteConfig{
		App:                     cfg.App,
		NotificationController:  notificationController,
		CorrelationIdMiddleware: correlationIdMiddleware,
		JwtMiddleware:           jwtMiddleware,
		Telemetry:               cfg.Telemetry,
	}
	routeConfig.Setup()

	// Notification Worker
	notificationWorker := worker.NewNotificationWorker(cfg.Log, cfg.Config, notificationHub)
	notificationWorker.Start(context.Background())
}
