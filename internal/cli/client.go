package cli

import (
	"context"
	"fmt"
	"time"

	pb "github.com/onbehalfofhim/secrets-keeper/api/proto"
	"github.com/onbehalfofhim/secrets-keeper/internal/grpcclient"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// DefaultRequestTimeout определяет максимальное время
// выполнения одного CLI-запроса.
const DefaultRequestTimeout = 30 * time.Second

// Client объединяет gRPC-клиентов Secrets Keeper.
type Client struct {
	conn *grpc.ClientConn

	Auth   pb.AuthServiceClient
	Secret pb.SecretServiceClient
	Binary pb.BinaryServiceClient

	tokenStore *TokenStore
}

// NewClient создаёт gRPC client.
// Подключение к серверу устанавливается при выполнении первого RPC.
func NewClient(cfg Config) (*Client, error) {
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("server address is empty")
	}

	conn, err := grpcclient.New(
		cfg.ServerAddr,
		cfg.CertFile,
		"localhost",
	)

	if err != nil {
		return nil, fmt.Errorf(
			"create gRPC client: %w",
			err,
		)
	}

	return &Client{
		conn:       conn,
		Auth:       pb.NewAuthServiceClient(conn),
		Secret:     pb.NewSecretServiceClient(conn),
		Binary:     pb.NewBinaryServiceClient(conn),
		tokenStore: NewTokenStore(cfg.TokenFile),
	}, nil
}

// Close закрывает gRPC connection.
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}

	return c.conn.Close()
}

// Context создаёт context с timeout для обычного RPC.
func (c *Client) Context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(
		context.Background(),
		DefaultRequestTimeout,
	)
}

// AuthenticatedContext создаёт context с JWT
// из локального TokenStore.
func (c *Client) AuthenticatedContext() (context.Context, context.CancelFunc, error) {
	token, err := c.tokenStore.Load()
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := c.Context()

	md := metadata.Pairs(
		"authorization",
		"Bearer "+token,
	)

	ctx = metadata.NewOutgoingContext(
		ctx,
		md,
	)

	return ctx, cancel, nil
}

// SaveToken сохраняет JWT.
func (c *Client) SaveToken(token string) error {
	return c.tokenStore.Save(token)
}

// DeleteToken удаляет JWT.
func (c *Client) DeleteToken() error {
	return c.tokenStore.Delete()
}
