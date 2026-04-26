package main

import (
	"flag"
	"fmt"
	"os"
)

type options struct {
	csvPath       string
	pcapPath      string
	outPath       string
	ignoreAttempt bool
}

func main() {
	opts, ok := parseOptions(os.Args)
	if !ok {
		os.Exit(1)
	}

	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, bool) {
	flags := flag.NewFlagSet(args[0], flag.ExitOnError)
	ignoreAttempt := flags.Bool("ignore-attempt", false, "do not treat labels containing Attempted as malicious")
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: %s [--ignore-attempt] <csv> <pcap> <output.pcap>\n", args[0])
		flags.PrintDefaults()
	}
	if err := flags.Parse(args[1:]); err != nil {
		return options{}, false
	}
	if flags.NArg() != 3 {
		flags.Usage()
		return options{}, false
	}

	return options{
		csvPath:       flags.Arg(0),
		pcapPath:      flags.Arg(1),
		outPath:       flags.Arg(2),
		ignoreAttempt: *ignoreAttempt,
	}, true
}

func run(opts options) error {
	fmt.Fprintf(os.Stderr, "Reading CSV: %s\n", opts.csvPath)
	index, stats, err := buildMaliciousIndex(opts.csvPath, opts.ignoreAttempt)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "CSV rows: %d, malicious: %d, attempted ignored: %d, bad protocol: %d, bad TCP/UDP ports: %d, unique keys: %d\n",
		stats.rows, stats.malicious, stats.attemptedIgnored, stats.badProtocol, stats.badTCPUDPPorts, len(index))

	fmt.Fprintf(os.Stderr, "Merging time windows...\n")
	mergeIndexWindows(index)

	return extractMatchingPackets(opts.pcapPath, opts.outPath, index)
}
