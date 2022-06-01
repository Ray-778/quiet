package flag

import (
	"quiet/actions"

	"github.com/urfave/cli/v2"
)

// ./main --iplist ip_list --port port_list --mode syn  --timeout 2 --concurrency 10
var PortScanCom = &cli.Command{
	Name:        "port scan",
	Usage:       "tcp syn/connect port scanner",
	Aliases:     []string{"ps", "p", "port"},
	Description: "start to scan port",
	Action:      actions.PortScan,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "iplist",
			Aliases: []string{"ip", "i"},
			Value:   "",
			Usage:   "ip list",
		},
		&cli.StringFlag{
			Name:    "port",
			Aliases: []string{"p"},
			Usage:   "port list",
		},
		&cli.StringFlag{
			Name:    "mode",
			Aliases: []string{"m"},
			Value:   "",
			Usage:   "port scan mode",
		},
		&cli.IntFlag{
			Name:    "timeout",
			Aliases: []string{"t"},
			Value:   2,
			Usage:   "timeout",
		},
		&cli.IntFlag{
			Name:    "concurrency",
			Aliases: []string{"c"},
			Value:   1000,
			Usage:   "concurrency",
		},
		&cli.BoolFlag{
			Name:    "local",
			Aliases: []string{"l"},
			Usage:   "local port scan",
		},
	},
}

// ./main --iplist ip_list --timeout 2 --concurrency 10
// ./main --domain domain --timeout 2 --concurrency 10
var ICMPScanCom = &cli.Command{
	Name:        "ICMP scan",
	Usage:       "ICMP scanner",
	Aliases:     []string{"icmpscan", "is", "ping"},
	Description: "start to ping a host",
	Action:      actions.ICMPScan,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "iplist",
			Aliases: []string{"ip", "i"},
			Usage:   "ip list",
		},
		&cli.StringFlag{
			Name:    "domain",
			Aliases: []string{"d"},
			Usage:   "domain",
		},
		&cli.IntFlag{
			Name:    "timeout",
			Aliases: []string{"t"},
			Value:   2,
			Usage:   "timeout",
		},
		&cli.IntFlag{
			Name:    "concurrency",
			Aliases: []string{"c"},
			Value:   1000,
			Usage:   "concurrency",
		},
		&cli.BoolFlag{
			Name:    "local",
			Aliases: []string{"l"},
			Usage:   "local ICMP scan",
		},
	},
}
