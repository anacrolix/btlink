package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	mathRand "math/rand"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anacrolix/bargle"
	"github.com/anacrolix/envpprof"
	"github.com/anacrolix/generics"
	"github.com/anacrolix/missinggo/v2/iter"
	"github.com/dgraph-io/ristretto"
	_ "github.com/honeycombio/honeycomb-opentelemetry-go"
	"github.com/honeycombio/opentelemetry-go-contrib/launcher"
	"github.com/multiformats/go-base36"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	main := bargle.Main{}
	main.Defer(envpprof.Stop)
	type encoderFunc func([]byte) string
	encoderChoices := bargle.Choices[encoderFunc]{
		"base64url": base64.URLEncoding.EncodeToString,
		"base36lc":  base36.EncodeToStringLc,
		"base32hex": base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString,
		"hex":       hex.EncodeToString,
	}
	main.Positionals = append(main.Positionals,
		bargle.Subcommand{Name: "proxy", Command: proxy()},
		bargle.Subcommand{Name: "gencert", Command: genCert()},
		bargle.Subcommand{Name: "extract-pubkey", Command: func() (cmd bargle.Command) {
			encoderChoice := bargle.NewChoice(encoderChoices)
			cmd.Options = append(cmd.Options, func() bargle.Param {
				m := bargle.NewUnaryOption(encoderChoice)
				m.AddLong("encoder")
				m.SetDefault("base36lc")
				return m.Make()
			}())
			var seed []byte
			{
				var encodedSeed string
				m := &bargle.Positional{
					Value: bargle.AutoUnmarshaler(&encodedSeed),
					Name:  "private-key",
					Desc:  "private key seed",
					AfterParseFunc: func(ctx bargle.Context) (err error) {
						seed, err = hex.DecodeString(encodedSeed)
						if err != nil {
							return
						}
						if len(seed) != ed25519.SeedSize {
							return fmt.Errorf("expected %v bytes, got %v", ed25519.SeedSize, len(seed))
						}
						return nil
					},
				}
				cmd.Positionals = append(cmd.Positionals, m)
			}
			cmd.DefaultAction = func() error {
				privKey := ed25519.NewKeyFromSeed(seed)
				fmt.Println(encoderChoice.Value()(privKey.Public().(ed25519.PublicKey)))
				return nil
			}
			return
		}()},
		bargle.Subcommand{Name: "convert", Command: func() (cmd bargle.Command) {
			cmd.Desc = "convert between different encodings used in btlink"
			type decoderFunc func(string) ([]byte, error)
			decoderChoice := bargle.NewChoice(bargle.Choices[decoderFunc]{
				"hex":       hex.DecodeString,
				"base36":    base36.DecodeString,
				"base32hex": base32.HexEncoding.DecodeString,
			})
			decoderParam := bargle.NewUnaryOption(decoderChoice)
			decoderParam.AddLong("from")
			decoderParam.AddShort('f')
			decoderParam.SetDefault("hex")
			encoderChoice := &bargle.Choice[encoderFunc]{Choices: encoderChoices}
			encoderParam := bargle.NewUnaryOption(encoderChoice)
			encoderParam.AddLong("to")
			encoderParam.AddShort('t')
			encoderParam.SetRequired()
			cmd.Options = append(cmd.Options,
				decoderParam.Make(),
				encoderParam.Make())
			var input generics.Option[string]
			cmd.Positionals = append(cmd.Positionals, &bargle.Positional{
				Name:  "input",
				Desc:  "data to decode",
				Value: bargle.NewOption(&input, nil),
			})
			cmd.DefaultAction = func() error {
				b, err := decoderChoice.Value()(input.Unwrap())
				if err != nil {
					return fmt.Errorf("error decoding input: %w", err)
				}
				fmt.Println(encoderChoice.Value()(b))
				return nil
			}
			return
		}()},
		bargle.Subcommand{Name: "generate-keys", Command: func() (cmd bargle.Command) {
			cmd.Desc = "search for progressively shorter valid public keys"
			parallelism := runtime.NumCPU()
			cmd.Options = append(cmd.Options, func() bargle.Param {
				m := bargle.NewUnaryOption(bargle.AutoUnmarshaler(&parallelism))
				m.AddLong("parallel")
				return m.Make()
			}())
			cmd.DefaultAction = func() error {
				var (
					mu       sync.Mutex
					tries    int64
					shortest = ""
				)
				for range iter.N(parallelism) {
					go func() {
						getPair := func() func() ([]byte, []byte) {
							if true {
								seed := make([]byte, ed25519.SeedSize)
								return func() ([]byte, []byte) {
									mathRand.Read(seed)
									privKey := ed25519.NewKeyFromSeed(seed)
									pubKey := privKey[ed25519.SeedSize:]
									return pubKey, seed
								}
							} else {
								return func() ([]byte, []byte) {
									pubKey, privKey, _ := ed25519.GenerateKey(nil)
									return pubKey, privKey.Seed()
								}
							}
						}()
						for {
							pubKey, seed := getPair()
							base36PubKey := base36.EncodeToStringLc(pubKey)
							mu.Lock()
							if shortest == "" || len(base36PubKey) < len(shortest) {
								shortest = base36PubKey
								seedBase36Lc := base36.EncodeToStringLc(seed)
								fmt.Printf("%s %s\n", base36PubKey, seedBase36Lc)
							}
							tries++
							mu.Unlock()
						}
					}()
				}
				var lastTries int64
				duration := time.Second
				for {
					time.Sleep(duration)
					mu.Lock()
					curTries := tries
					mu.Unlock()
					log.Printf("%v tries/s", (curTries-lastTries)/int64(duration/time.Second))
					duration *= 2
					lastTries = curTries
				}
			}
			return
		}()},
	)
	main.Run()
}

func proxy() (cmd bargle.Command) {
	cmd.Desc = "run proxy/gateway combo"
	var (
		confluenceHost    string
		confluenceScheme  string
		httpPortInt       uint16 = 42080
		httpsPortInt      uint16 = 44369
		gatewayDomains    []string
		logRequestHeaders bool
	)
	opt := bargle.NewUnaryOption(bargle.AutoUnmarshaler(&confluenceHost))
	opt.AddLong("confluence-host")
	opt.AddShort('h')
	opt.SetRequired()
	cmd.Options = append(cmd.Options, opt.Make())
	opt = bargle.NewUnaryOption(bargle.AutoUnmarshaler(&confluenceScheme))
	opt.AddLong("confluence-scheme")
	opt.AddShort('s')
	opt.SetRequired()
	cmd.Options = append(cmd.Options, opt.Make())
	opt = bargle.NewUnaryOption(bargle.AutoUnmarshaler(&httpPortInt))
	opt.AddLong("http-port")
	cmd.Options = append(cmd.Options, opt.Make())
	opt = bargle.NewUnaryOption(bargle.AutoUnmarshaler(&httpsPortInt))
	opt.AddLong("https-port")
	cmd.Options = append(cmd.Options, opt.Make())
	opt = bargle.NewUnaryOption(bargle.AutoUnmarshaler(&gatewayDomains))
	opt.AddLong("gateway-domain")
	opt.AddShort('g')
	opt.Description(`whitelist of domain roots to issue certificates for`)
	cmd.Options = append(cmd.Options, opt.Make())
	flagOpt := bargle.NewFlag(&logRequestHeaders)
	flagOpt.AddLong("log-request-headers")
	cmd.Options = append(cmd.Options, flagOpt.Make())
	cmd.DefaultAction = func() error {
		shutdownTelemetry, err := launcher.ConfigureOpenTelemetry()
		if err != nil {
			err = fmt.Errorf("configuring open telemetry: %w", err)
			// Silly honeycomb helper has a newline in the error message. Not cool.
			log.Printf("%q", err)
		} else {
			defer shutdownTelemetry()
		}
		confluenceClientCert, err := tls.LoadX509KeyPair("confluence.pem", "confluence.pem")
		if err != nil {
			log.Printf("error loading confluence client cert: %v", err)
		}
		dhtItemCache, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: 30,
			// So we can trigger this sooner for testing.
			MaxCost:     3,
			BufferItems: 64,
			// Because we don't represent the cost of cache items using bytes, but ristretto will add
			// the internal cost for the key in bytes.
			IgnoreInternalCost: true,
			OnExit: func(val interface{}) {
				v := val.(*dhtItemCacheValue)
				log.Printf("value removed from dht item cache [target=%v]", v.target)
			},
		})
		if err != nil {
			return fmt.Errorf("new dht item cache: %w", err)
		}
		infoCache, err := ristretto.NewCache(&ristretto.Config{
			NumCounters: 10000,
			MaxCost:     50e6,
			BufferItems: 64,
		})
		if err != nil {
			return fmt.Errorf("new info cache: %w", err)
		}
		handler := gatewayHandler{
			confluence: confluenceHandler{
				confluenceHost:   confluenceHost,
				confluenceScheme: confluenceScheme,
				confluenceTransport: otelhttp.NewTransport(&http.Transport{
					TLSClientConfig: &tls.Config{
						Certificates:       []tls.Certificate{confluenceClientCert},
						InsecureSkipVerify: true,
					},
				}),
			},
			dhtItemCache:    dhtItemCache,
			dirPageTemplate: htmlTemplates.Lookup("dir.html"),
			metainfoCache:   infoCache,
		}
		httpPort := strconv.FormatUint(uint64(httpPortInt), 10) // Make the default 42080
		httpAddr := ":" + httpPort
		httpsPort := strconv.FormatUint(uint64(httpsPortInt), 10) // Make sure default is 44369
		httpsAddr := ":" + httpsPort
		proxyMux := http.NewServeMux()
		proxyMux.HandleFunc("/.btlink/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
			err := serveDynamicPac(w, r, httpPort, httpsPort)
			if err != nil {
				log.Printf("error serving dynamic pac: %v", err)
			}
		})
		proxyMux.HandleFunc("/.btlink/rootca.pem", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "ca.pem")
		})
		autocertManager := autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache:  autocert.DirCache("autocert-cache"),
			HostPolicy: func(ctx context.Context, host string) error {
				// Note that this doesn't match a specific proxy domain (which we can't just use
				// Cloudflare for due to CONNECT). If the proxy domain isn't the same as one of the
				// gateway domains, more configuration is required here. There's also no checking that
				// the requested domain name is valid, which would reduce unnecessary certificate
				// issuance. Lastly, if there is rate-limiting applied, it might be worth looking into
				// ACME DNS challenges to obtain wildcard certificates.
				for _, gd := range gatewayDomains {
					if host == gd || strings.HasSuffix(host, "."+gd) {
						return nil
					}
				}
				return errors.New("no gateway domains matched")
			},
			Email:    "anacrolix+btlink@gmail.com",
			ShortSAN: "btlink.anacrolix.link",
		}
		proxyHandler := func(logPrefix string) http.Handler {
			return otelhttp.NewHandler(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if logRequestHeaders {
						log.Printf("%v: received request\n%s", logPrefix, requestLogString(r))
					}
					err := func() error {
						// Connect can be passed to a HTTPS proxy endpoint. We want to handle this
						// ourselves, so we loop it back too. This also works if we receive CONNECT over HTTPS.
						if r.Method == http.MethodConnect {
							// We serve TLS by looping back to the HTTPS handler on this host.
							log.Printf("handling proxy request for %q", requestUrl(r))
							handleConnect(w, "localhost"+httpsAddr, r)
							return nil
						}
						if handler.ServeHTTP(w, r) {
							return nil
						}
						log.Printf("handling proxy request for %q", requestUrl(r))
						proxyMux.ServeHTTP(w, r)
						return nil
					}()
					if err != nil {
						log.Printf("%v: error in proxy handler: %v", logPrefix, err)
					}
				}),
				logPrefix,
			)
		}
		serverErrs := make(chan error, 2)
		go func() {
			log.Printf("starting http server at %q", httpAddr)
			err := http.ListenAndServe(httpAddr, autocertManager.HTTPHandler(proxyHandler("http server")))
			log.Printf("http server returned: %v", err)
			serverErrs <- err
		}()
		if true {
			go func() {
				var certs []tls.Certificate
				cert, err := tls.LoadX509KeyPair("wildcard.bt.pem", "ca.key")
				if err != nil {
					log.Printf("error loading bt wildcard cert: %v", err)
				} else {
					certs = append(certs, cert)
				}
				cert, err = tls.LoadX509KeyPair("localhost.pem", "ca.key")
				if err != nil {
					log.Printf("error loading localhost cert: %v", err)
				} else {
					certs = append(certs, cert)
				}
				tlsConfig := &tls.Config{
					GetCertificate: func(info *tls.ClientHelloInfo) (_ *tls.Certificate, err error) {
						for _, cert := range certs {
							if info.SupportsCertificate(&cert) == nil {
								return &cert, nil
							}
						}
						started := time.Now()
						defer func() {
							elapsed := time.Since(started)
							if elapsed > time.Second {
								go log.Printf("getting certificate for %q took %v: %v", info.ServerName, elapsed, err)
							}
						}()
						return autocertManager.GetCertificate(info)
					},
				}
				s := http.Server{
					Addr:      httpsAddr,
					Handler:   proxyHandler("tls http server"),
					TLSConfig: tlsConfig,
					// TODO: Test this with Safari using HTTPS then falling back to HTTP proxying.
					ReadHeaderTimeout: 5 * time.Second,
				}
				log.Printf("starting https server at %q", s.Addr)
				err = s.ListenAndServeTLS("", "")
				log.Printf("https server returned: %v", err)
				serverErrs <- err
			}()
		}
		return fmt.Errorf("server error: %w", <-serverErrs)
	}
	return
}
