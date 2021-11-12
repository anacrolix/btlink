package main

import (
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/anacrolix/args"
	"github.com/anacrolix/envpprof"
	"github.com/dgraph-io/ristretto"
	"github.com/multiformats/go-base36"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	log.SetFlags(log.Flags() | log.Lshortfile)
	defer envpprof.Stop()
	err := mainErr()
	if err != nil {
		log.Printf("error in main: %v", err)
	}
}

func mainErr() error {
	args.ParseMain(
		args.Subcommand("proxy", proxy),
		args.Subcommand("gencert", genCert),
		args.Subcommand("convert", func(ctx args.SubCmdCtx) (err error) {
			var input string
			decoderChoice := args.Choice{
				Long: "from",
				Choices: map[string]interface{}{
					"hex":       hex.DecodeString,
					"base36":    base36.DecodeString,
					"base32hex": base32.HexEncoding.DecodeString,
				},
				Default: "hex",
			}
			encoderChoice := args.Choice{
				Long: "to",
				Choices: map[string]interface{}{
					"base64url": base64.URLEncoding.EncodeToString,
					"base36lc":  base36.EncodeToStringLc,
					"base32hex": base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString,
					"hex":       hex.EncodeToString,
				},
			}
			ctx.Parse(
				args.Pos("input", &input),
				decoderChoice.ToParam(),
				encoderChoice.ToParam())
			b, err := decoderChoice.SelectedValue().(func(string) ([]byte, error))(input)
			if err != nil {
				return fmt.Errorf("error decoding input: %w", err)
			}
			fmt.Println(encoderChoice.SelectedValue().(func([]byte) string)(b))
			return nil
		}),
	)
	return nil
}

func proxy(scc args.SubCmdCtx) error {
	var confluenceHost, confluenceScheme string
	var httpPortInt, httpsPortInt uint16 = 42080, 44369
	logRequestHeaders := args.Flag(args.FlagOpt{
		Long: "log-request-headers",
	})
	scc.Parse(
		args.Opt(args.OptOpt{
			Long:     "confluence-host",
			Target:   &confluenceHost,
			Short:    'h',
			Required: true,
		}),
		args.Opt(args.OptOpt{
			Long:     "confluence-scheme",
			Target:   &confluenceScheme,
			Short:    's',
			Required: true,
		}),
		args.Opt(args.OptOpt{
			Long:   "http-port",
			Target: &httpPortInt,
		}),
		args.Opt(args.OptOpt{
			Long:   "https-port",
			Target: &httpsPortInt,
		}),
		logRequestHeaders,
	)
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
			log.Printf("value removed from dht item cache [item=%v]", v)
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
	handler := handler{
		confluence: confluenceHandler{
			confluenceHost:   confluenceHost,
			confluenceScheme: confluenceScheme,
			confluenceTransport: http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates:       []tls.Certificate{confluenceClientCert},
					InsecureSkipVerify: true,
				},
			},
		},
		dhtItemCache: dhtItemCache,
		dirPageTemplate: template.Must(template.New("dir").Parse(`
<body style="font-family:monospace">
	<p>$ ls</p>
	<table>
		<tr><th>File</th><th>Size</th></tr>
		{{ range .Children -}}
		<tr>
			<td><a href="{{.Href}}">{{.Name}}</a></td>
			<td>{{.Size}}</td>
		</tr>
		{{- end }}
	</table>
</body>`,
		)),
		infoCache: infoCache,
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
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("autocert-cache"),
		HostPolicy: autocert.HostWhitelist("btlink.anacrolix.link"),
		Email:      "anacrolix+btlink@gmail.com",
	}
	proxyHandler := func(logPrefix string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if logRequestHeaders.Bool() {
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
				if handler.serveBtLink(w, r) {
					return nil
				}
				log.Printf("handling proxy request for %q", requestUrl(r))
				proxyMux.ServeHTTP(w, r)
				return nil
			}()
			if err != nil {
				log.Printf("%v: error in proxy handler: %v", logPrefix, err)
			}
		})
	}
	serverErrs := make(chan error, 2)
	go func() {
		log.Printf("starting http server at %q", httpAddr)
		err := http.ListenAndServe(httpAddr, autocertManager.HTTPHandler(proxyHandler("http server")))
		log.Printf("http server returned: %v", err)
		serverErrs <- err
	}()
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
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				for _, cert := range certs {
					if info.SupportsCertificate(&cert) == nil {
						return &cert, nil
					}
				}
				return autocertManager.GetCertificate(info)
			},
		}
		s := http.Server{
			Addr:        httpsAddr,
			Handler:     proxyHandler("tls http server"),
			TLSConfig:   tlsConfig,
			ReadTimeout: 5 * time.Second,
		}
		log.Printf("starting https server at %q", s.Addr)
		err = s.ListenAndServeTLS("", "")
		log.Printf("https server returned: %v", err)
		serverErrs <- err
	}()
	return fmt.Errorf("server error: %w", <-serverErrs)
}
