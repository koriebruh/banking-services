package config

import (
	"golang-clean-architecture/internal/delivery/http"
	"golang-clean-architecture/internal/delivery/http/middleware"
	"golang-clean-architecture/internal/delivery/http/route"
	"golang-clean-architecture/internal/gateway/grpc"
	"golang-clean-architecture/internal/gateway/messaging"
	"golang-clean-architecture/internal/repository"
	"golang-clean-architecture/internal/usecase"

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
}

func Bootstrap(config *BootstrapConfig) {
	// LOAD PUBLIC KEY FOR JWT
	if err := middleware.LoadPublicKey(config.Config, config.Log); err != nil {
		config.Log.Fatalf("Failed to load JWT public key: %v", err)
	}

	// INIT
	publisher := messaging.NewTransferEventPublisher(config.KafkaProducer, config.Log, config.Config)
	transferRepository := repository.NewTransferRepository(config.Log)
	transferUseCase := usecase.NewTransferUseCase(
		config.DB,
		config.Log,
		config.Validate,
		transferRepository,
		publisher,
		config.Grpc,
	)
	transferController := http.NewTransferController(config.Log, transferUseCase)

	// MIDDLEWARE
	correlationIdMiddleware := middleware.CorrelationID(config.Log)
	jwtMiddleware := middleware.JWTProtected(config.Log)

	routeConfig := route.RouteConfig{
		App:                     config.App,
		TransferController:      transferController,
		CorrelationIdMiddleware: correlationIdMiddleware,
		JwtMiddleware:           jwtMiddleware,
	}
	routeConfig.Setup()
}
