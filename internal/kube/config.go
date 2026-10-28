// Package kube is a small Kubernetes API client: kubeconfig, in-cluster config and the few ExternalSecret
// calls wellhead makes. See docs/adrs/0002 for why it is not client-go.
package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

type kubeconfig struct {
	CurrentContext string `yaml:"current-context"`
	Clusters       []struct {
		Name    string  `yaml:"name"`
		Cluster cluster `yaml:"cluster"`
	} `yaml:"clusters"`
	Users []struct {
		Name string   `yaml:"name"`
		User authInfo `yaml:"user"`
	} `yaml:"users"`
	Contexts []struct {
		Name    string `yaml:"name"`
		Context struct {
			Cluster   string `yaml:"cluster"`
			User      string `yaml:"user"`
			Namespace string `yaml:"namespace"`
		} `yaml:"context"`
	} `yaml:"contexts"`
}

type cluster struct {
	Server                   string `yaml:"server"`
	CertificateAuthority     string `yaml:"certificate-authority"`
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify"`
	TLSServerName            string `yaml:"tls-server-name"`
}

type authInfo struct {
	Token                 string      `yaml:"token"`
	TokenFile             string      `yaml:"tokenFile"`
	ClientCertificate     string      `yaml:"client-certificate"`
	ClientCertificateData string      `yaml:"client-certificate-data"`
	ClientKey             string      `yaml:"client-key"`
	ClientKeyData         string      `yaml:"client-key-data"`
	Exec                  *execConfig `yaml:"exec"`
	AuthProvider          any         `yaml:"auth-provider"`
}

type execConfig struct {
	APIVersion string   `yaml:"apiVersion"`
	Command    string   `yaml:"command"`
	Args       []string `yaml:"args"`
	Env        []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"env"`
	ProvideClusterInfo bool `yaml:"provideClusterInfo"`
}

// Config is a resolved connection to one API server.
type Config struct {
	Server    string
	Namespace string
	HTTP      *http.Client
	token     func(context.Context) (string, error)
}

// Options select the kubeconfig and context.
type Options struct {
	Kubeconfig string
	Context    string
}

// Load resolves a connection: the kubeconfig named in options or $KUBECONFIG (first file that exists),
// then ~/.kube/config, then the in-cluster service account.
func Load(o Options) (*Config, error) {
	path := o.Kubeconfig
	if path == "" {
		for _, p := range filepath.SplitList(os.Getenv("KUBECONFIG")) {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}
	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			p := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(p); err == nil {
				path = p
			}
		}
	}
	if path == "" {
		if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
			return inCluster()
		}
		return nil, errors.New("no kubeconfig: set KUBECONFIG or pass --kubeconfig")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return fromKubeconfig(data, filepath.Dir(path), o.Context)
}

func fromKubeconfig(data []byte, base, contextName string) (*Config, error) {
	var kc kubeconfig
	if err := yaml.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	if contextName == "" {
		contextName = kc.CurrentContext
	}
	var clusterName, userName, ns string
	found := false
	for _, c := range kc.Contexts {
		if c.Name == contextName {
			clusterName, userName, ns, found = c.Context.Cluster, c.Context.User, c.Context.Namespace, true
		}
	}
	if !found {
		return nil, fmt.Errorf("kubeconfig: no context %q", contextName)
	}
	var cl *cluster
	for i := range kc.Clusters {
		if kc.Clusters[i].Name == clusterName {
			cl = &kc.Clusters[i].Cluster
		}
	}
	if cl == nil {
		return nil, fmt.Errorf("kubeconfig: context %q names unknown cluster %q", contextName, clusterName)
	}
	var user authInfo
	for _, u := range kc.Users {
		if u.Name == userName {
			user = u.User
		}
	}
	if user.AuthProvider != nil {
		return nil, fmt.Errorf("kubeconfig: user %q uses a legacy auth-provider; switch it to an exec plugin", userName)
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cl.TLSServerName, InsecureSkipVerify: cl.InsecureSkipTLSVerify} //nolint:gosec // honours the kubeconfig's own insecure-skip-tls-verify
	ca, err := bytesFrom(cl.CertificateAuthorityData, cl.CertificateAuthority, base)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: certificate-authority: %w", err)
	}
	if len(ca) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, errors.New("kubeconfig: certificate-authority holds no PEM certificate")
		}
		tlsConf.RootCAs = pool
	}
	cert, err := bytesFrom(user.ClientCertificateData, user.ClientCertificate, base)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: client-certificate: %w", err)
	}
	key, err := bytesFrom(user.ClientKeyData, user.ClientKey, base)
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: client-key: %w", err)
	}
	if len(cert) > 0 {
		pair, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("kubeconfig: client certificate: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{pair}
	}
	if ns == "" {
		ns = "default"
	}
	c := &Config{
		Server:    strings.TrimRight(cl.Server, "/"),
		Namespace: ns,
		HTTP:      &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConf, Proxy: http.ProxyFromEnvironment}},
	}
	switch {
	case user.Token != "":
		tok := user.Token
		c.token = func(context.Context) (string, error) { return tok, nil }
	case user.TokenFile != "":
		p := resolve(base, user.TokenFile)
		c.token = func(context.Context) (string, error) { return readTrim(p) }
	case user.Exec != nil:
		c.token = execToken(user.Exec, c, tlsConf)
	}
	return c, nil
}

func inCluster() (*Config, error) {
	const dir = "/var/run/secrets/kubernetes.io/serviceaccount/"
	ca, err := os.ReadFile(dir + "ca.crt")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	ns, _ := readTrim(dir + "namespace")
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return &Config{
		Server:    "https://" + host + ":" + os.Getenv("KUBERNETES_SERVICE_PORT"),
		Namespace: ns,
		HTTP:      &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}},
		token:     func(context.Context) (string, error) { return readTrim(dir + "token") },
	}, nil
}

func execToken(e *execConfig, c *Config, tlsConf *tls.Config) func(context.Context) (string, error) {
	var mu sync.Mutex
	var cached string
	var expiry time.Time
	return func(ctx context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if cached != "" && (expiry.IsZero() || time.Until(expiry) > time.Minute) {
			return cached, nil
		}
		api := e.APIVersion
		if api == "" {
			api = "client.authentication.k8s.io/v1"
		}
		info := map[string]any{"apiVersion": api, "kind": "ExecCredential", "spec": map[string]any{"interactive": false}}
		if e.ProvideClusterInfo {
			info["spec"].(map[string]any)["cluster"] = map[string]any{"server": c.Server, "tls-server-name": tlsConf.ServerName}
		}
		infoJSON, _ := json.Marshal(info)
		cmd := exec.CommandContext(ctx, e.Command, e.Args...) //nolint:gosec // runs the credential plugin the kubeconfig names, as kubectl does
		cmd.Env = append(os.Environ(), "KUBERNETES_EXEC_INFO="+string(infoJSON))
		for _, kv := range e.Env {
			cmd.Env = append(cmd.Env, kv.Name+"="+kv.Value)
		}
		var out bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("kubeconfig exec plugin %s: %w", e.Command, err)
		}
		var cred struct {
			Status struct {
				Token               string    `json:"token"`
				ExpirationTimestamp time.Time `json:"expirationTimestamp"`
			} `json:"status"`
		}
		if err := json.Unmarshal(out.Bytes(), &cred); err != nil {
			return "", fmt.Errorf("kubeconfig exec plugin %s: %w", e.Command, err)
		}
		if cred.Status.Token == "" {
			return "", fmt.Errorf("kubeconfig exec plugin %s returned no token; client certificates from a plugin are not supported", e.Command)
		}
		cached, expiry = cred.Status.Token, cred.Status.ExpirationTimestamp
		return cached, nil
	}
}

func bytesFrom(data, file, base string) ([]byte, error) {
	if data != "" {
		return base64.StdEncoding.DecodeString(data)
	}
	if file != "" {
		return os.ReadFile(resolve(base, file))
	}
	return nil, nil
}

func resolve(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

func readTrim(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
