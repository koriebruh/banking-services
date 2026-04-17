package main

import (
	"context"
	"fmt"
	"golang-clean-architecture/internal/config"
)

func main() {
	viperConfig := config.NewViper()
	log := config.NewLogger(viperConfig)
	app := config.NewFiber(viperConfig)

	tel, err := config.NewTelemetry(context.Background(), viperConfig, log)

	if err != nil {
		log.Fatalf("Failed to initialize telemetry: %v", err)
	}

	if tel != nil {
		defer tel.TracerProvider.Shutdown(context.Background())
		defer tel.MeterProvider.Shutdown(context.Background())
	}

	config.Bootstrap(&config.BootstrapConfig{
		App:           app,
		Log:           log,
		Config:        viperConfig,
		Telemetry:     tel,
	})

	webPort := viperConfig.GetInt("web.port")
	err = app.Listen(fmt.Sprintf(":%d", webPort))
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
