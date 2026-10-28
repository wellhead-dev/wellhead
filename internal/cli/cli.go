// Package cli implements the wellhead commands.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wellhead-dev/wellhead/internal/kube"
	"github.com/wellhead-dev/wellhead/internal/prompt"
	"github.com/wellhead-dev/wellhead/internal/redact"
	"github.com/wellhead-dev/wellhead/internal/vault"
	"github.com/wellhead-dev/wellhead/internal/verify"
)

// Cluster is the part of the Kubernetes API wellhead uses.
type Cluster interface {
	ListExternalSecrets(ctx context.Context, ns string) ([]map[string]any, error)
	GetExternalSecret(ctx context.Context, ns, name string) (map[string]any, error)
	GetStore(ctx context.Context, kind, ns, name string) (map[string]any, error)
	ForceSync(ctx context.Context, ns, name string, now time.Time) error
	WaitReady(ctx context.Context, ns, name string, since time.Time, every time.Duration) (kube.Condition, error)
}

// Vault is the part of the KV v2 API wellhead uses.
type Vault interface {
	Read(ctx context.Context, mount, path string) (*vault.Secret, error)
	Write(ctx context.Context, mount, path string, data map[string]string, version int) (int, error)
	MergeMetadata(ctx context.Context, mount, path string, custom map[string]string) error
	Self(ctx context.Context) (string, error)
}

// ClusterOptions select a kubeconfig and context.
type ClusterOptions struct {
	Kubeconfig string
	Context    string
}

// Deps is everything the commands need from outside; cmd/wellhead wires it from the environment.
type Deps struct {
	Version     string
	Stdout      io.Writer
	Stderr      io.Writer
	Prompt      prompt.Prompter
	Interactive bool
	Now         func() time.Time
	Verifiers   verify.Registry
	Cluster     func(ClusterOptions) (Cluster, error)
	Vault       func() (Vault, error)
	SeededBy    string
	PollEvery   time.Duration
}

const usage = `wellhead makes every ExternalSecret declare where its value comes from.

Usage:
  wellhead lint [--store NAME]... [--exclude GLOB]... [PATH]...
  wellhead missing [--namespace NS] [--verify] [--all]
  wellhead seed [--rotate] [--no-sync] [--timeout 2m] NAMESPACE/NAME [FIELD=@FILE]...
  wellhead version

missing and seed read the cluster from KUBECONFIG and the vault from VAULT_ADDR and VAULT_TOKEN
(or BAO_ADDR and BAO_TOKEN). Exit status: 0 clean, 1 findings, 2 usage or connection errors.
`

// Run runs one command and returns its exit status.
func Run(ctx context.Context, args []string, d Deps) int {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Verifiers == nil {
		d.Verifiers = verify.Default()
	}
	if d.PollEvery == 0 {
		d.PollEvery = 2 * time.Second
	}
	if len(args) == 0 {
		_, _ = fmt.Fprint(d.Stderr, usage)
		return 2
	}
	secrets := &redact.Set{}
	var err error
	code := 0
	switch args[0] {
	case "lint":
		code, err = lint(args[1:], d)
	case "missing":
		code, err = missing(ctx, args[1:], d, secrets)
	case "seed":
		code, err = seed(ctx, args[1:], d, secrets)
	case "version", "--version":
		_, _ = fmt.Fprintln(d.Stdout, d.Version)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(d.Stdout, usage)
	default:
		_, _ = fmt.Fprintf(d.Stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintln(d.Stderr, "wellhead: "+secrets.Error(err).Error())
		if code == 0 {
			code = 2
		}
	}
	return code
}

type multi []string

func (m *multi) String() string { return strings.Join(*m, ",") }

func (m *multi) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func flags(name string, d Deps) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(d.Stderr)
	return fs
}
