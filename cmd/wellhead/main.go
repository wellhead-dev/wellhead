// Command wellhead finds, seeds, verifies and lints the values External Secrets Operator ExternalSecrets read.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/wellhead-dev/wellhead/internal/cli"
	"github.com/wellhead-dev/wellhead/internal/kube"
	"github.com/wellhead-dev/wellhead/internal/prompt"
	"github.com/wellhead-dev/wellhead/internal/vault"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	term := prompt.NewTerminal()
	code := cli.Run(ctx, os.Args[1:], cli.Deps{
		Version:     version,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Prompt:      term,
		Interactive: term.Interactive(),
		SeededBy:    os.Getenv("WELLHEAD_SEEDED_BY"),
		Cluster: func(o cli.ClusterOptions) (cli.Cluster, error) {
			cfg, err := kube.Load(kube.Options{Kubeconfig: o.Kubeconfig, Context: o.Context})
			if err != nil {
				return nil, err
			}
			return kube.New(cfg), nil
		},
		Vault: vaultFromEnv,
	})
	stop()
	os.Exit(code)
}

func env(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func vaultFromEnv() (cli.Vault, error) {
	addr := env("VAULT_ADDR", "BAO_ADDR")
	if addr == "" {
		return nil, errors.New("set VAULT_ADDR or BAO_ADDR")
	}
	token := env("VAULT_TOKEN", "BAO_TOKEN")
	if token == "" {
		if home, err := os.UserHomeDir(); err == nil {
			for _, f := range []string{".vault-token", ".bao-token"} {
				if b, err := os.ReadFile(filepath.Join(home, f)); err == nil {
					token = strings.TrimSpace(string(b))
					break
				}
			}
		}
	}
	if token == "" {
		return nil, errors.New("set VAULT_TOKEN or BAO_TOKEN, or log in with the vault or bao CLI")
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca := env("VAULT_CACERT", "BAO_CACERT"); ca != "" {
		pem, err := os.ReadFile(ca) //nolint:gosec // the CA file the person configured
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New(ca + " holds no PEM certificate")
		}
		tlsConf.RootCAs = pool
	}
	return &vault.Client{
		Addr:      addr,
		Token:     token,
		Namespace: env("VAULT_NAMESPACE", "BAO_NAMESPACE"),
		HTTP:      &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConf, Proxy: http.ProxyFromEnvironment}},
	}, nil
}
