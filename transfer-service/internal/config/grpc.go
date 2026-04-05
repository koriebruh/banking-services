package config

import (
	"golang-clean-architecture/internal/gateway/grpc"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func NewGrpc(config *viper.Viper, log *logrus.Logger) *grpc.AccountGrpcClient {
	addr := config.GetString("grpc.server")

	accountGrpcClient, err := grpc.NewAccountGrpcClient(addr, log)
	if err != nil {
		log.Fatal("Failed to connect to account-service gRPC:", err)
	}
	log.Infof("gRPC connected to account-service at %s", addr)
	return accountGrpcClient
}
