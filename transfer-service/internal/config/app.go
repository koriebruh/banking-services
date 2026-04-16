package config

import (
	"context"

	"golang-clean-architecture/internal/delivery/http"
	"golang-clean-architecture/internal/delivery/http/middleware"
	"golang-clean-architecture/internal/delivery/http/route"
	"golang-clean-architecture/internal/gateway/grpc"
	"golang-clean-architecture/internal/gateway/messaging"
	"golang-clean-architecture/internal/repository"
	"golang-clean-architecture/internal/telemetry"
	"golang-clean-architecture/internal/usecase"
	"golang-clean-architecture/internal/worker"

	"github.com/IBM/sarama"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gorm.io/gorm"
)

type BootstrapConfig struct {
	DB            *gorm.DB
	App           *fiber.App
	Log           *logrus.Logger
	Validate      *validator.Validate
	Config        *viper.Viper
	KafkaProducer sarama.SyncProducer
	Grpc          *grpc.AccountGrpcClient
	Telemetry     *telemetry.Providers
}

func Bootstrap(cfg *BootstrapConfig) {
	// LOAD PUBLIC KEY FOR JWT
	if err := middleware.LoadPublicKey(cfg.Config, cfg.Log); err != nil {
		cfg.Log.Fatalf("Failed to load JWT public key: %v", err)
	}

	// INIT
	publisher := messaging.NewTransferEventPublisher(cfg.KafkaProducer, cfg.Log, cfg.Config)

	// Start Worker Outbox
	outboxWorker := worker.NewOutboxWorker(cfg.DB, cfg.Log, publisher)
	outboxWorker.Start(context.Background())

	transferRepository := repository.NewTransferRepository(cfg.Log)
	transferUseCase := usecase.NewTransferUseCase(
		cfg.DB,
		cfg.Log,
		cfg.Validate,
		transferRepository,
		publisher,
		cfg.Grpc,
	)
	transferController := http.NewTransferController(cfg.Log, transferUseCase)

	// HEALTH
	healthController := http.NewHealthController(cfg.Log, cfg.DB)

	// MIDDLEWARE
	correlationIdMiddleware := middleware.CorrelationID(cfg.Log)
	jwtMiddleware := middleware.JWTProtected(cfg.Log)

	//
	routeConfig := route.RouteConfig{
		App:                     cfg.App,
		TransferController:      transferController,
		HealthController:        healthController,
		CorrelationIdMiddleware: correlationIdMiddleware,
		JwtMiddleware:           jwtMiddleware,
		Telemetry:               cfg.Telemetry,
	}
	routeConfig.Setup()
}
