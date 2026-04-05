package main

import (
	"fmt"
	"golang-clean-architecture/internal/config"
)

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	db := config.NewDatabase(viperConfig, log)
	validate := config.NewValidator(viperConfig)
	app := config.NewFiber(viperConfig)
	producer := config.NewKafkaProducer(viperConfig, log)
	grpc := config.NewGrpc(viperConfig, log)

	config.Bootstrap(&config.BootstrapConfig{
		DB:            db,
		App:           app,
		Log:           log,
		Validate:      validate,
		Config:        viperConfig,
		KafkaProducer: producer,
		Grpc:          grpc,
	})

	webPort := viperConfig.GetInt("web.port")
	err := app.Listen(fmt.Sprintf(":%d", webPort))
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
