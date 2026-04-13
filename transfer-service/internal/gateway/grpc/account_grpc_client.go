package grpc

import (
	"context"
	"fmt"
	"golang-clean-architecture/internal/gateway/grpc/pb"
	"time"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// AccountGrpcClient function as a client to connect into Grpc server
type AccountGrpcClient struct {
	client pb.AccountGrpcServiceClient
	log    *logrus.Logger
}

func NewAccountGrpcClient(address string, log *logrus.Logger) (*AccountGrpcClient, error) {
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	)
	if err != nil {
		return nil, err
	}

	return &AccountGrpcClient{
		client: pb.NewAccountGrpcServiceClient(conn),
		log:    log,
	}, nil
}

// ValidateAccount checks if account is ACTIVE and has sufficient balance.
// Called before persisting transfer as PENDING.
func (c *AccountGrpcClient) ValidateAccount(ctx context.Context, accountNumber, amount, currency string) (*pb.ValidateAccountResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.client.ValidateAccount(ctx, &pb.ValidateAccountRequest{
		AccountNumber: accountNumber,
		Amount:        amount,
		Currency:      currency,
	})
	if err != nil {
		c.log.Errorf("[gRPC] ValidateAccount failed accountNumber=%s: %v", accountNumber, err)
		return nil, err
	}

	if !resp.Valid {
		c.log.Warnf("[gRPC] Account invalid accountNumber=%s reason=%s", accountNumber, resp.Reason)
		return nil, fmt.Errorf(resp.Reason)
	}

	return resp, nil
}

// GetAccountDetail fetches account metadata — used to get account_id for target account.
func (c *AccountGrpcClient) GetAccountDetail(ctx context.Context, accountNumber string) (*pb.AccountDetailResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := c.client.GetAccountDetail(ctx, &pb.GetAccountDetailRequest{
		AccountNumber: accountNumber,
	})
	if err != nil {
		c.log.Errorf("[gRPC] GetAccountDetail failed accountNumber=%s: %v", accountNumber, err)
		return nil, err
	}

	return resp, nil
}
