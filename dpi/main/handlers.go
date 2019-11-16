package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"encoding/json"
	"os"
	"regexp"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"

	"github.com/flier/gohs/hyperscan"
)

// var c = make(chan int)
var sig = make(chan string)

type MatchContext struct {
	// packetData []byte
	hdrsLen       uintptr
	currentPacket *packet.Packet
	result        bool
}

// HSdb keeps Hyperscan db and scratches
type HSdb struct {
	// Bdb is Hyperscan block database
	Bdb hyperscan.BlockDatabase
	// Scratches keep separate scratch for each handler
	Scratches *hyperscan.Scratch
}

// Pattern describes one regex and action on match (allow/disallow packet)
type Pattern struct {
	Name   string
	Regexp string
	Re     *regexp.Regexp
	Allow  bool
}

type HyperScanContext struct {
	// eth layers.Ethernet
	// ip4 layers.IPv4
	// ip6 layers.IPv6
	// tcp layers.TCP
	// udp layers.UDP
	// parser *gopacket.DecodingLayerParser
	// handlerID uint
	hsdbActive HSdb
	hsdbShadow HSdb
	c          chan int

	// hsdbShadow  	pattern.HSdb
	// patterns []Pattern
}

func (ctx HyperScanContext) Delete() {
	fmt.Println("Delete called")
	ctx.hsdbActive.Bdb.Close()
	ctx.hsdbShadow.Bdb.Close()
	ctx.hsdbActive.Scratches.Free()
	ctx.hsdbShadow.Scratches.Free()
}

// var Globalpattern Pattern

//Create new counters for new handler
func (ctx HyperScanContext) Copy() interface{} {

	fmt.Println("Copy called")
	newCtx := new(HyperScanContext)
	//  = GetPatternsFromFile("pat.json")
	newCtx.hsdbActive.SetupHyperscan()
	newCtx.hsdbShadow.SetupHyperscan()
	newCtx.c = make(chan int)
	return newCtx
}

func onMatch(id uint, from, to uint64, flags uint, context interface{}) error {
	isMatch := context.(*MatchContext)
	hdrsLen := isMatch.hdrsLen
	currentPacket := isMatch.currentPacket

	for i := uint(0); i < currentPacket.GetPacketLen(); i++ {
		*(*byte)(currentPacket.StartAtOffset(uintptr(hdrsLen + uintptr(i)))) = 0
	}

	// Report outside that match was found
	isMatch.result = true
	return nil
}

var count uint8 = 0

func filterByHS(pkt *packet.Packet, context flow.UserContext) bool {
	// fmt.Println("recieving packets")
	ctx := context.(*HyperScanContext)
	// var hsdb HSdb
	pktStartAddr := pkt.StartAtOffset(0)
	pktBytes := pkt.GetRawPacketBytes()
	if pkt.ParseDataCheckVLAN() == -1 {
		return false
	}
	hdrsLen := uintptr(pkt.Data) - uintptr(pktStartAddr)
	packetData := pktBytes[hdrsLen:]

	select {
	case signal := <-sig:
		fmt.Println("launching go routine", signal)
		go ctx.hsdbShadow.CleanupHyperscan(ctx)

	default:
		// fmt.Println("case default")
	}

	matchCtx := new(MatchContext)
	matchCtx.currentPacket = pkt
	matchCtx.hdrsLen = hdrsLen

	select {
	case msg := <-ctx.c:
		if msg == 1 {
			// hsdb = ctx.hsdbActive
			if err := ctx.hsdbActive.Bdb.Scan(packetData, ctx.hsdbActive.Scratches, onMatchCallback, matchCtx); err != nil {
				// fmt.Println("error 1 returning false")
				return false
			}

		} else if msg == 2 {
			// hsdb = ctx.hsdbShadow
			if err := ctx.hsdbShadow.Bdb.Scan(packetData, ctx.hsdbShadow.Scratches, onMatchCallback, matchCtx); err != nil {
				// fmt.Println("error 1 returning false")
				return false
			}
		} else if msg == 3 {
			// hsdb = ctx.hsdbActive
			if err := ctx.hsdbActive.Bdb.Scan(packetData, ctx.hsdbActive.Scratches, onMatchCallback, matchCtx); err != nil {
				// fmt.Println("error 1 returning false")
				return false
			}
		}
	default:
		// hsdb = ctx.hsdbActive
		if err := ctx.hsdbActive.Bdb.Scan(packetData, ctx.hsdbActive.Scratches, onMatchCallback, matchCtx); err != nil {
			// fmt.Println("error 1 returning false")
			return false
		}
		// fmt.Println("case default")
	}
	return matchCtx.result
	// return true
}

func status(filename string) {
	var count int
	var count1 int = 1
	for {

		time.Sleep(1 * time.Second)
		content, err := ioutil.ReadFile("status")
		if err != nil {
			log.Fatal(err)
		}
		s := string(content[0])
		if s == "1" {
			if count1 == 1 {
				fmt.Println("getting new patterns from file")
				patterns, _ := GetPatternsFromFile("pat.json")
				unparsed := getAllowPatterns(patterns)
				parsed = parsePatterns(unparsed)
				fmt.Println(parsed[0])
				count1++
			}
			sig <- s
			count = count + 1
			if count == 8 {
				break
			}
			// break
		}
	}
}

// GetPatternsFromFile reads JSON file
func GetPatternsFromFile(filename string) ([]Pattern, error) {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	patterns := make([]Pattern, 0)
	if err := json.Unmarshal(f, &patterns); err != nil {
		fmt.Println(err)
		return nil, err
	}
	// fmt.Println(patterns)
	return patterns, nil
}

// SetupHyperscan makes setup of Hyperscan DB and preallocates Scratches
func (hsdb *HSdb) SetupHyperscan() {
	// unparsed := getAllowPatterns(patterns)
	// parsed := parsePatterns(unparsed)
	// fmt.Println("Unparsed patterns: ", unparsed)
	var err error
	fmt.Println("Creating new database")
	hsdb.Bdb, err = hyperscan.NewBlockDatabase(parsed...)
	fmt.Println("Created new database")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not compile patterns, %s", err)
		os.Exit(-1)
	}

	// Allocate one scratch per flow
	// for i := uint(0); i < NumFlows; i++ {
	hsdb.Scratches, err = hyperscan.NewScratch(hsdb.Bdb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could sot allocate scratch space for block db: %s", err)
		os.Exit(-1)
		// }
	}
	// if err := hsdb.Scratches.Realloc(hsdb.Bdb); err != nil {
	// 	fmt.Errorf("could not reallocate scratch space, %s", err)
	// }
}

func (hsdb *HSdb) UpdateHyperscan() {
	// unparsed := getAllowPatterns(patterns)
	// parsed := parsePatterns(unparsed)
	// fmt.Println("Unparsed patterns: ", unparsed)
	var err error
	fmt.Println("Creating new database")
	hsdb.Bdb, err = hyperscan.NewBlockDatabase(parsed...)
	fmt.Println("Created new database")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not compile patterns, %s", err)
		os.Exit(-1)
	}

	// Allocate one scratch per flow
	// for i := uint(0); i < NumFlows; i++ {
	// hsdb.Scratches, err = hyperscan.NewScratch(hsdb.Bdb)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "ERROR: Could sot allocate scratch space for block db: %s", err)
	// 	os.Exit(-1)
	// 	// }
	// }
	if err := hsdb.Scratches.Realloc(hsdb.Bdb); err != nil {
		fmt.Errorf("could not reallocate scratch space, %s", err)
	}
}

// CleanupHyperscan close DB and deallocate Scratches
func (hsdb *HSdb) CleanupHyperscan(ctx *HyperScanContext) {

	ctx.c <- 1
	// ctx.hsdbShadow.Bdb.Close()
	// paterns, _ := GetPatternsFromFile("pat.json")
	ctx.hsdbShadow.UpdateHyperscan()

	ctx.c <- 2

	// ctx.hsdbActive.Bdb.Close()
	// paterns, _ = GetPatternsFromFile("pat.json")
	ctx.hsdbActive.UpdateHyperscan()
	ctx.c <- 3

}

func getAllowPatterns(patterns []Pattern) (ret []string) {
	for _, p := range patterns {
		if p.Allow == true {
			ret = append(ret, p.Regexp)
		}
	}
	if len(ret) == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: no 'allow' rules in file. HS mode support only allow rules")
		os.Exit(-1)
	}
	return
}

func parsePatterns(unparsed []string) (patterns []*hyperscan.Pattern) {
	for k, v := range unparsed {
		p, err := hyperscan.ParsePattern(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: could not parse pattern: %s", err)
			os.Exit(-1)
		}
		p.Id = k
		patterns = append(patterns, p)
	}
	return
}
