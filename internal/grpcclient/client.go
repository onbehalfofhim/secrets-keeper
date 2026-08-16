package grpcclient

import (
	"crypto/x509"
	"fmt"
	"os"

	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func New(addr string, certFile string, serverName string) (*grpc.ClientConn, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS certificate: %w", err)
	}

	certPool := x509.NewCertPool()

	if ok := certPool.AppendCertsFromPEM(certPEM); !ok {
		return nil, fmt.Errorf("failed to append TLS certificate")
	}

	tlsConfig := &tls.Config{
		RootCAs:    certPool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}

	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(
			credentials.NewTLS(tlsConfig),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create gRPC connection: %w", err)
	}

	return conn, nil
}
