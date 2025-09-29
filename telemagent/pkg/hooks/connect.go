package hooks

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/rand"
	"net/url"
	"strconv"
	"strings"

	"github.com/snapcore/snapd/telemagent/pkg/utils"

	mptls "github.com/snapcore/snapd/telemagent/pkg/tls"

	"github.com/caarlos0/env/v11"
	"github.com/canonical/mqtt.golang/autopaho"
	"github.com/canonical/mqtt.golang/paho"
	mochi "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/snapcore/snapd/client"
)

const DeniedTopic = "DENIED"
const ErrorTopic = "ERROR"

type Config struct {
	Enabled   bool   `env:"ENABLED"     envDefault:"false"`
	Endpoint  string `env:"ENDPOINT"     envDefault:"mqtt://localhost:1883"`
	Port      int    `env:"PORT"     envDefault:"9090"`
	TLSConfig *tls.Config
}

// Options contains configuration settings for the hook.
type ConnectHookOptions struct {
	Server     *mochi.Server
	mqttConfig autopaho.ClientConfig
	mqttClient *autopaho.ConnectionManager
	router     paho.Router
	Cfg        Config
}

type ConnectHook struct {
	mochi.HookBase
	config *ConnectHookOptions
}

func NewConfig(opts env.Options) (Config, error) {
	c := Config{}
	if err := env.ParseWithOptions(&c, opts); err != nil {
		return Config{}, err
	}

	cfg, err := mptls.NewConfig(opts)
	if err != nil {
		return Config{}, err
	}

	c.TLSConfig, err = mptls.LoadClient(&cfg)
	if err != nil {
		return Config{}, err
	}

	return c, nil
}

func (h *ConnectHook) Init(config any) error {
	h.Log.Info("initialised")
	if _, ok := config.(*ConnectHookOptions); !ok && config != nil {
		return mochi.ErrInvalidConfigType
	}

	h.config = config.(*ConnectHookOptions)
	if h.config.Server == nil {
		return mochi.ErrInvalidConfigType
	}

	snapClient := client.New(nil)

	macaroon, err := snapClient.DeviceSession()
	if err != nil {
		h.Log.Error(err.Error())
	}

	deviceID, err := utils.GetDeviceId()
	if err != nil {
		h.Log.Warn(err.Error())
	}

	h.Log.Info(fmt.Sprintf("Acquired device session macaroon: %s", macaroon[0]))

	u, err := url.Parse(h.config.Cfg.Endpoint)
	if err != nil {
		return err
	}

	router := paho.NewStandardRouter()

	cliCfg := autopaho.ClientConfig{
		ServerUrls:                    []*url.URL{u},
		KeepAlive:                     20,
		CleanStartOnInitialConnection: false,
		SessionExpiryInterval:         60,
		TlsCfg:                        h.config.Cfg.TLSConfig,
		OnConnectionUp: func(cm *autopaho.ConnectionManager, connAck *paho.Connack) {
			h.Log.Info(fmt.Sprintf("Server connected to MQTT broker on address %s", h.config.Cfg.Endpoint))
		},
		OnConnectError:  func(err error) { h.Log.Error(fmt.Sprintf("error whilst attempting connection: %s\n", err)) },
		ConnectUsername: deviceID,
		ConnectPassword: []byte(macaroon[0]),
		ConnectPacketBuilder: func(cp *paho.Connect, u *url.URL) (*paho.Connect, error) {
			if cp.Properties == nil {
				cp.Properties = &paho.ConnectProperties{}
			}
			cp.Properties.User = append(cp.Properties.User, paho.UserProperty{Key: "client-type", Value: "device"})
			return cp, nil
		},
		ClientConfig: paho.ClientConfig{
			ClientID:      deviceID + "-" + strconv.Itoa(1e4+rand.Int()%9e4),
			OnClientError: func(err error) { h.Log.Error(fmt.Sprintf("client error: %s\n", err)) },
			OnPublishReceived: []func(paho.PublishReceived) (bool, error){
				func(p paho.PublishReceived) (bool, error) {
					h.config.router.Route(p.Packet.Packet())
					return false, nil
				},
			},
			OnServerDisconnect: func(d *paho.Disconnect) {
				h.Log.Info(fmt.Sprintf("server requested disconnect; reason code: %d\n", d.ReasonCode))
			},
		},
	}

	h.config.mqttConfig = cliCfg
	h.config.router = router
	return nil
}

func (h *ConnectHook) ID() string {
	return "detect-snap"
}

func (h *ConnectHook) Provides(b byte) bool {
	return bytes.Contains([]byte{
		mochi.OnConnectAuthenticate,
		mochi.OnSubscribe,
		mochi.OnACLCheck,
		mochi.OnPublish,
		mochi.OnPacketEncode,
		mochi.OnStarted,
	}, []byte{b})
}

func (h *ConnectHook) OnConnectAuthenticate(cl *mochi.Client, pk packets.Packet) bool {

	snapPublisher, snapName, err := utils.GetSnapInfoFromConn(cl.Net.Conn.RemoteAddr().String())

	if err != nil {
		h.Log.Error(fmt.Sprintf("failed to get snap info: %v", err))
		return false
	}

	h.Log.Info(fmt.Sprintf("receieved packet from snap %s - %s", snapName, snapPublisher))

	return true
}

func (h *ConnectHook) OnSubscribe(cl *mochi.Client, pk packets.Packet) packets.Packet {
	var err error
	var snapPublisher string
	var snapName string

	if snapPublisher, snapName, err = utils.GetSnapInfoFromConn(cl.Net.Conn.RemoteAddr().String()); err != nil {
		h.Log.Warn("Could not get snap publisher")
		return packets.Packet{Filters: packets.Subscriptions{{Filter: ErrorTopic}}}
	}

	for i := range pk.Filters {
		if (pk.Filters)[i].Filter[0] != '/' {
			var newTopic string

			if (pk.Filters)[i].Filter[0] != '$' {
				newTopic = fmt.Sprintf("/+/%s/%s", snapPublisher, (pk.Filters)[i].Filter)
			} else {
				h.Log.Error("Local namespace topics cannot start with $")
				(pk.Filters)[i].Filter = DeniedTopic
				continue
			}

			(pk.Filters)[i].Filter = newTopic

			msg := fmt.Sprintf("Topic converted to global namespace, subscribing now to %s", (pk.Filters)[i].Filter)
			h.Log.Info(msg)
		} else {
			if isValid := checkPublisher((pk.Filters)[i].Filter, snapName, snapPublisher, h.Log); !isValid {
				continue
			}
		}

		if _, err := h.config.mqttClient.Subscribe(context.Background(), &paho.Subscribe{
			Subscriptions: []paho.SubscribeOptions{
				{Topic: (pk.Filters)[i].Filter, QoS: 2},
			},
		}); err != nil {
			h.Log.Error(fmt.Sprintf("failed to subscribe (%s). This is likely to mean no messages will be received.", err))
		}
	}

	return pk
}

func checkPublisher(topic, snapName, snapPublisher string, logger *slog.Logger) bool {
	return true
}

func (h *ConnectHook) OnACLCheck(cl *mochi.Client, topic string, write bool) bool {
	if write {
		return true
	}

	if topic == ErrorTopic || topic == DeniedTopic {
		h.Log.Info("Topic rejected")
		return false
	}

	return true
}

func (h *ConnectHook) OnPublish(cl *mochi.Client, pk packets.Packet) (packets.Packet, error) {
	var err error
	var snapPublisher string
	var snapName string

	if cl.Net.Inline {
		return pk, nil
	}

	if snapPublisher, snapName, err = utils.GetSnapInfoFromConn(cl.Net.Conn.RemoteAddr().String()); err != nil {
		h.Log.Warn("Could not get snap publisher")
		return packets.Packet{}, errors.New("failed to get snap publisher")
	}

	if (pk.TopicName)[0] == '/' {
		snapClient := client.New(nil)

		if isAllowed, err := isAllowedTopic(snapClient, pk.TopicName, snapName, snapPublisher, "pub"); err != nil || !isAllowed {
			h.Log.Warn("Topic is not allowed for publishing")
			pk.TopicName = DeniedTopic
		}
	} else {
		deviceId, err := utils.GetDeviceId()
		if err != nil {
			h.Log.Warn(err.Error())
		}

		if (pk.TopicName)[0] == '$' {
			h.Log.Error("Local namespace topic cannot start with $")
			(pk.TopicName) = DeniedTopic
			// error will be caught by interceptor
			return packets.Packet{}, errors.New("Local namespace topic cannot start with $")
		}

		newTopic := fmt.Sprintf("/%s/%s/%s", deviceId, snapPublisher, pk.TopicName)

		msg := fmt.Sprintf("Converting topic %s to global namespace, prepending topic with snap name %s", pk.TopicName, snapPublisher)
		h.Log.Info(msg)

		pk.TopicName = newTopic
	}

	if _, err := h.config.mqttClient.Publish(context.Background(), &paho.Publish{
		QoS:     2,
		Topic:   pk.TopicName,
		Payload: pk.Payload,
		Retain:  pk.FixedHeader.Retain,
	}); err != nil {
		return packets.Packet{}, err
	}

	return packets.Packet{}, errors.New("Client won't publish")
}

func isAllowedTopic(snapClient *client.Client, topic, snapName, snapPublisher, action string) (bool, error) {
	levels := strings.Split(topic, "/")[1:]
	if len(levels) < 2 {
		return false, fmt.Errorf("invalid topic: no snap publisher")
	}

	if levels[1] == snapPublisher {
		return true, nil
	}

	if action == "pub" {
		return false, nil
	}

	return false, nil
}

func (h *ConnectHook) OnPacketEncode(cl *mochi.Client, pk packets.Packet) packets.Packet {
	if pk.FixedHeader.Type == packets.Publish {
		levels := strings.Split(pk.TopicName, "/")
		levels = levels[1:]
		if len(levels) > 1 {
			var err error
			var snapPublisher string

			if snapPublisher, _, err = utils.GetSnapInfoFromConn(cl.Net.Conn.RemoteAddr().String()); err != nil {
				h.Log.Warn("Could not get snap publisher")
				return pk
			}

			deviceId, err := utils.GetDeviceId()
			if err != nil {
				h.Log.Warn(err.Error())
			}

			if deviceId == levels[0] && snapPublisher == levels[1] {
				levels = levels[2:]
			}

			newTopic := strings.Join(levels, "/")
			pk.TopicName = newTopic

			h.Log.Info("Removed global namespace.")
		} else {
			h.Log.Warn("Could not find global namespace, leaving topic as is.")
		}
		return pk
	}

	return pk
}

func (h *ConnectHook) OnStarted() {
	ctx := context.Background()

	h.config.mqttConfig.OnPublishReceived = append(h.config.mqttConfig.OnPublishReceived, func(pr paho.PublishReceived) (bool, error) {
		if err := h.config.Server.Publish(pr.Packet.Topic, pr.Packet.Payload, pr.Packet.Retain, pr.Packet.QoS); err != nil {
			return false, err
		}

		h.Log.Info("Server received message from external broker, will resend")
		return true, nil
	})

	c, err := autopaho.NewConnection(ctx, h.config.mqttConfig) // starts process; will reconnect until context cancelled
	if err != nil {
		log.Fatalf("could not connect to remote broker: %v", err)
	}

	h.config.mqttClient = c
	// Wait for the connection to come up
	if err = h.config.mqttClient.AwaitConnection(ctx); err != nil {
		log.Fatalf("could not connect to remote broker: %v", err)
	}

}
