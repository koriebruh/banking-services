package config

import (
	"golang-clean-architecture/internal/gateway/grpc"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func NewGrpc(config *viper.Viper, log *logrus.Logger) *grpc.AccountGrpcClient {
	accountGrpcClient, err := grpc.NewAccountGrpcClient(
		config.GetString("grpc.server"), log,
	)
	if err != nil {
		log.Fatal("Failed to connect to account-service gRPC:", err)
	}
	return accountGrpcClient
}
