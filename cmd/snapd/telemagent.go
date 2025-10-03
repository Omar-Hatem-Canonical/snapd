package main

import (
<<<<<<< HEAD
=======
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
>>>>>>> fb2c88504c (feat: update github lib)
	"log"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

<<<<<<< HEAD
	"github.com/snapcore/snapd/telemagent/pkg/hooks"

	"github.com/caarlos0/env/v11"
=======
	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/telemagent/pkg/hooks"
	mptls "github.com/snapcore/snapd/telemagent/pkg/tls"

>>>>>>> fb2c88504c (feat: update github lib)
	mochi "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/listeners"
)

const mqttPrefix = "MQTT_"

func telemagent() {

	// Create signals channel to run server until interrupted
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		done <- true
	}()

	// Create Logger
	logHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove time attribute
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			return a
		},
	})

	// rest HTTP server Configuration
<<<<<<< HEAD
	serverConfig, err := hooks.NewConfig(env.Options{Prefix: mqttPrefix})
=======
	serverConfig, err := buildConfig()
>>>>>>> fb2c88504c (feat: update github lib)
	if err != nil {
		panic(err)
	}

	// Create logger with custom handler
	logger := slog.New(logHandler)

<<<<<<< HEAD
=======
	// addEnv(logger)

>>>>>>> fb2c88504c (feat: update github lib)
	// Create the new MQTT Server.
	server := mochi.New(&mochi.Options{
		Logger:       logger,
		InlineClient: true,
	})

	// Allow all connections.
	err = server.AddHook(new(hooks.TelemAgentHook), &hooks.TelemAgentHookOptions{
		Server: server,
<<<<<<< HEAD
		Cfg:    serverConfig,
=======
		Cfg:    *serverConfig,
>>>>>>> fb2c88504c (feat: update github lib)
	})

	if err != nil {
		log.Fatal(err)
	}

	// Create a TCP listener on a standard port.
<<<<<<< HEAD
	tcp := listeners.NewTCP(listeners.Config{ID: "t1", Address: serverConfig.BrokerPort})
=======
	tcp := listeners.NewTCP(listeners.Config{
		ID:        "t1",
		Address:   serverConfig.BrokerPort,
		TLSConfig: serverConfig.TLSConfig,
	})
>>>>>>> fb2c88504c (feat: update github lib)
	err = server.AddListener(tcp)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		err := server.Serve()
		if err != nil {
			log.Fatal(err)
		}
	}()

	// Run server until interrupted
	<-done

	// Cleanup
<<<<<<< HEAD
}

func addEnv() {
	os.Setenv("MQTT_ENDPOINT", "mqtt://demo.staging:1883")
	os.Setenv("MQTT_BROKER_PORT", ":1885")
=======
}

func addEnv(logger *slog.Logger) {

	snapClient := client.New(nil)

	if os.Getenv("MQTT_ENDPOINT") == "" {
		logger.Info("config was empty")
		os.Setenv("MQTT_ENDPOINT", "mqtt://demo.staging:1883")

		_, err := snapClient.SetConf("system", map[string]any{"telemagent.endpoint": "mqtt://demo.staging:1883"})
		if err != nil {
			logger.Error(err.Error())
		}
	}

	if os.Getenv("MQTT_BROKER_PORT") == "" {
		os.Setenv("MQTT_BROKER_PORT", ":1885")

		_, err := snapClient.SetConf("system", map[string]any{"telemagent.port": ":1885"})
		if err != nil {
			logger.Error(err.Error())
		}
	}

	if os.Getenv("MQTT_SERVER_CA_FILE") == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			logger.Error(err.Error())
		}
		sslDir := filepath.Join(home, ".ssl")

		certFile, serverCAFile, keyFile, err := generateCertificates(sslDir)
		if err != nil {
			logger.Error(err.Error())
		}
		os.Setenv("MQTT_CERT_FILE", certFile)
		os.Setenv("MQTT_KEY_FILE", keyFile)
		os.Setenv("MQTT_SERVER_CA_FILE", serverCAFile)

		_, err = snapClient.SetConf("system", map[string]any{"telemagent.ca-cert": serverCAFile})
		if err != nil {
			logger.Error(err.Error())
		}

	}

	logger.Info("loaded env vars")
}

func generateCertificates(outDir string) (string, string, string, error) {
	// Create output directory if missing
	err := os.MkdirAll(outDir, 0700) // user-only access
	if err != nil {
		return "", "", "", err
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2025),
		Subject: pkix.Name{
			Organization: []string{"Local CA"},
			CommonName:   "Local MQTT Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	caCertBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	var caCertPEM bytes.Buffer
	pem.Encode(&caCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes})

	// Server Keypair and signing
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	serverTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2048),
		Subject: pkix.Name{
			Organization: []string{"telem-agent"},
			CommonName:   "localhost",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	var serverCertPEM bytes.Buffer
	pem.Encode(&serverCertPEM, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})

	var serverKeyPEM bytes.Buffer
	pem.Encode(&serverKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)})

	// Write to files
	caPath := filepath.Join(outDir, "ca.crt")
	certPath := filepath.Join(outDir, "cert.crt")
	keyPath := filepath.Join(outDir, "key.crt")

	err = os.WriteFile(caPath, caCertPEM.Bytes(), 0644)
	if err != nil {
		return "", "", "", err
	}
	err = os.WriteFile(certPath, serverCertPEM.Bytes(), 0644)
	if err != nil {
		return "", "", "", err
	}
	err = os.WriteFile(keyPath, serverKeyPEM.Bytes(), 0600) // key should be protected
	if err != nil {
		return "", "", "", err
	}

	return caPath, certPath, keyPath, nil
}

func buildConfig() (*hooks.Config, error) {
	snapClient := client.New(nil)

	var cfg hooks.Config

	confs, err := snapClient.Conf("system", []string{"telemagent.endpoint"})
	if err != nil {
		return nil, err
	}

	for _, conf := range confs {
		confStr, ok := conf.(string)
		if !ok {
			return nil, errors.New("cannot convert to string")
		}

		if confStr == "" {
			_, err := snapClient.SetConf("system", map[string]any{"telemagent.endpoint": "mqtt://demo.staging:1883"})
			if err != nil {
				return nil, err
			}
		}

		cfg.Endpoint = "mqtt://demo.staging:1883"
	}

	confs, err = snapClient.Conf("system", []string{"telemagent.port"})
	if err != nil {
		return nil, err
	}

	for _, conf := range confs {
		confStr, ok := conf.(string)
		if !ok {
			return nil, errors.New("cannot convert to string")
		}

		if confStr == "" {
			_, err := snapClient.SetConf("system", map[string]any{"telemagent.port": ":1885"})
			if err != nil {
				return nil, err
			}
		}

		cfg.BrokerPort = ":1885"
	}

	confs, err = snapClient.Conf("system", []string{"telemagent.ca-cert"})
	if err != nil {
		return nil, err
	}

	for _, conf := range confs {
		confStr, ok := conf.(string)
		if !ok {
			return nil, errors.New("cannot convert to string")
		}

		if confStr == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			sslDir := filepath.Join(home, ".ssl")
			certFile, serverCAFile, keyFile, err := generateCertificates(sslDir)
			if err != nil {
				return nil, err
			}

			_, err = snapClient.SetConf("system", map[string]any{"telemagent.ca-cert": serverCAFile})
			if err != nil {
				return nil, err
			}

			tlsCfg := mptls.Config{
				CertFile:     certFile,
				ServerCAFile: serverCAFile,
				KeyFile:      keyFile,
			}

			cfg.TLSConfig, err = mptls.Load(&tlsCfg)
			if err != nil {
				return nil, err
			}

		}
	}

	return &cfg, nil
>>>>>>> fb2c88504c (feat: update github lib)
}
