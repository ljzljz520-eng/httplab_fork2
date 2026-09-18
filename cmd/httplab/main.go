package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/gchaincl/httplab/security"
	"github.com/gchaincl/httplab/ui"
	"github.com/jroimartin/gocui"
	"github.com/rs/cors"
	flag "github.com/spf13/pflag"
)

const VERSION = "v0.4.0-dev"

func NewHandler(ui *ui.UI, g *gocui.Gui) http.Handler {
	fn := func(w http.ResponseWriter, req *http.Request) {
		if err := ui.AddRequest(g, req); err != nil {
			ui.Info(g, "%s", err.Error())
		}

		resp := ui.Response()
		time.Sleep(resp.Delay)
		resp.Write(w)

	}
	return http.HandlerFunc(fn)
}

func defaultConfigPath() string {
	var path = ".httplab"

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return path
	}

	u, err := user.Current()
	if err != nil {
		return path
	}

	return u.HomeDir + "/" + path
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nBindings:\n%s", ui.Bindings.Help())
}

func Version() {
	fmt.Fprintf(os.Stdout, "%s\n", VERSION)
	os.Exit(0)
}

type options struct {
	config           string
	policyPath       string
	revealTTL        time.Duration
	auditRetention   time.Duration
	captureRetention time.Duration
	captureDir       string
	noCapture        bool
}

func main() {
	var (
		port        int
		config      string
		version     bool
		corsEnabled bool
		corsDisplay bool
		opts        options
	)

	flag.Usage = usage

	flag.IntVarP(&port, "port", "p", 10080, "Specifies the port where HTTPLab will bind to.")
	flag.StringVarP(&config, "config", "c", "", "Specifies custom config path.")
	flag.BoolVarP(&version, "version", "v", false, "Prints current version.")
	flag.BoolVar(&corsEnabled, "cors", false, "Enable CORS.")
	flag.BoolVar(&corsDisplay, "cors-display", true, "Display CORS requests")

	flag.StringVar(&opts.policyPath, "policy", "", "Path to the data classification policy JSON (defaults to <config>.policy.json when present).")
	flag.DurationVar(&opts.revealTTL, "reveal-ttl", 15*time.Second, "How long a sensitive-value reveal stays authorized.")
	flag.DurationVar(&opts.auditRetention, "audit-retention", 7*24*time.Hour, "How long audit records are kept before being purged.")
	flag.DurationVar(&opts.captureRetention, "capture-retention", 24*time.Hour, "How long encrypted on-disk captures are kept before being purged.")
	flag.StringVar(&opts.captureDir, "capture-dir", "", "Directory for envelope-encrypted request captures (defaults to <config>.captures; empty plus --no-capture disables it).")
	flag.BoolVar(&opts.noCapture, "no-capture", false, "Disable the encrypted on-disk request capture store.")

	flag.Parse()

	if version {
		Version()
	}

	opts.config = config

	// noop
	middleware := func(next http.Handler) http.Handler {
		return next
	}

	if corsEnabled {
		middleware = cors.New(cors.Options{
			OptionsPassthrough: corsDisplay,
		}).Handler
	}

	if err := run(port, middleware, opts); err != nil && err != gocui.ErrQuit {
		log.Println(err)
	}
}

func run(port int, middleware func(next http.Handler) http.Handler, opts options) error {
	if opts.config == "" {
		opts.config = defaultConfigPath()
	}
	if opts.policyPath == "" {
		opts.policyPath = opts.config + ".policy.json"
	}

	captureDir := opts.captureDir
	if captureDir == "" && !opts.noCapture {
		captureDir = opts.config + ".captures"
	}

	guard, err := security.NewGuard(security.Config{
		PolicyPath:       opts.policyPath,
		KeyPath:          opts.config + ".key",
		AuditPath:        opts.config + ".audit.log",
		CaptureDir:       captureDir,
		MasterKey:        os.Getenv("HTTPLAB_MASTER_KEY"),
		RevealTTL:        opts.revealTTL,
		AuditRetention:   opts.auditRetention,
		CaptureRetention: opts.captureRetention,
	})
	if err != nil {
		return err
	}
	defer guard.Close()
	guard.StartMaintenance(time.Hour)

	g, err := gocui.NewGui(gocui.Output256)
	if err != nil {
		log.Fatalln(err)
	}
	defer g.Close()

	ui := ui.New(opts.config, guard)
	errCh, err := ui.Init(g)
	if err != nil {
		return err
	}

	http.Handle("/", middleware(NewHandler(ui, g)))
	go func() {
		// Make sure gocui has started
		g.Execute(func(g *gocui.Gui) error { return nil })

		ui.Info(g, "Listening on :%d (KEK: %s)", port, guard.Keys.Source())
		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
			errCh <- err
		}
	}()

	return g.MainLoop()
}
