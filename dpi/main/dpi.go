// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/flier/gohs/hyperscan"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/examples/dpi/pattern"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

// Sample input pcap files can be downloaded from http://wiresharkbook.com/studyguide.html
// For example:
// http-cnn2012.pcapng
// http-facebook.pcapng
// http-downloadvideo.pcapng
// google-http.pcapng
//
// Note: only pcap format is supported. Convert pcapng to pcap:
// editcap -F pcap http-facebook.pcapng http-facebook.pcap
//
// Rules file requirements:
// In regexp mode:
//		Rules in file should go in increasing priority.
//		Rules are checked in the order they are in the file.
// 		Each next rule is more specific and refines (or overwrites) result
// 		of previous rules check.
//		Support 'allow'/'disallow' rules.
// In hyperscan mode:
// 		Rules has equal priority and are checked all at once.
//		For match enough at least one match of any pattern.
//		Support only 'allow' rules, 'disallow' rules are skipped.

var (
	infile  string
	outfile string
	nreads  int
	timeout time.Duration
	useHS   bool

	// Number of allowed packets for each flow
	// allowedPktsCount [pattern.NumFlows]uint64
	// Number of read packets for each flow
	// readPktsCount [pattern.NumFlows]uint64
	// Number of packets blocked by signature for each flow
	// blockedPktsCount [pattern.NumFlows]uint64

	// Global Hyperscan database can be uses by several handlers
	hsdb1 pattern.HSdb
	hsdb2 pattern.HSdb
	// patterns []Pattern
	// unparsed []string
	parsed []*hyperscan.Pattern

	packetFilter    func(*packet.Packet, flow.UserContext) bool
	onMatchCallback hyperscan.MatchHandler = onMatch
)

func main() {
	fmt.Println("In main")
	flag.StringVar(&infile, "infile", "", "input pcap file")
	flag.StringVar(&outfile, "outfile", "allowed-packets.pcap", "output pcap file with allowed packets")
	flag.IntVar(&nreads, "nreads", 1, "number pcap file reads")
	flag.DurationVar(&timeout, "timeout", 20*time.Second, "time to run, seconds")
	flag.BoolVar(&useHS, "hs", true, "use Intel Hyperscan library for regex match (default is go regexp)")
	flag.Parse()
	patterns, _ := GetPatternsFromFile("pat.json")
	unparsed := getAllowPatterns(patterns)
	parsed = parsePatterns(unparsed)
	fmt.Println(parsed[0])

	dpdkargs := []string{"-w 0000:41:00.0", "--file-prefix=zeeshan"}
	config := flow.Config{

		CPUList:    "1,3,5,7,9,19,21,23,25,27,29,31",
		DPDKArgs:   dpdkargs,
		LogType:    common.No,
		MbufNumber: 65535,

		MbufCacheSize: 500,
		RingSize:      4096,
		// LogType: common

		// MemoryJumbo: true,
	}

	// Initialize NFF-Go library
	flow.CheckFatal(flow.SystemInit(&config))

	var err error
	// fmt.Println("inmain")
	go status("status")
	flow.CheckFatal(err)

	// fmt.Println("\n\n\n\n using Hyperscan RegExp")
	packetFilter = filterByHS
	// hsdb1.SetupHyperscan(patterns)
	// hsdb2.SetupHyperscan(patterns1)

	inputFlow, _ := flow.SetReceiver(0)

	var ctx HyperScanContext

	wlFlow, _ := flow.SetSeparator(inputFlow, packetFilter, ctx)

	flow.CheckFatal(flow.SetSender(wlFlow, 0))
	// flow.CheckFatal(flow.SetSenderOS(wlFlow, "em1"))
	// flow.SetStopper(wlFlow)
	flow.SetSenderFile(inputFlow, "/root/res.pcap")
	flow.CheckFatal(flow.SystemStart())

}
