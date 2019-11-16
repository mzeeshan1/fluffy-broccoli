package pattern

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"

	"github.com/flier/gohs/hyperscan"
)

// HSdb keeps Hyperscan db and scratches
type HSdb struct {
	// Bdb is Hyperscan block database
	Bdb hyperscan.BlockDatabase
	// Scratches keep separate scratch for each handler
	Scratches *hyperscan.Scratch
	Updated   bool
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
	hsdb HSdb
	// hsdbShadow  	pattern.HSdb
	patterns []Pattern
}

// GetPatternsFromFile reads JSON file
func GetPatternsFromFile(filename string) ([]Pattern, error) {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	patterns := make([]Pattern, 0)
	if err := json.Unmarshal(f, &patterns); err != nil {
		return nil, err
	}
	// fmt.Println(patterns)
	return patterns, nil
}

// SetupHyperscan makes setup of Hyperscan DB and preallocates Scratches
func (hsdb *HSdb) SetupHyperscan(patterns []Pattern) {
	unparsed := getAllowPatterns(patterns)
	parsed := parsePatterns(unparsed)
	var err error
	fmt.Println("Creating new database for: ", parsed)
	hsdb.Bdb, err = hyperscan.NewBlockDatabase(parsed...)
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
	hsdb.Updated = true
}

// CleanupHyperscan close DB and deallocate Scratches
func (hsdb *HSdb) CleanupHyperscan(ctx *HyperScanContext) {

	fmt.Println("Cleaning up hyperscan DB")
	// for i := uint(0); i < NumFlows; i++ {
	hsdb.Scratches.Free()
	// }
	hsdb.Bdb.Close()
	fmt.Println("Setting up DB update")
	paterns, _ := GetPatternsFromFile("patjson.json")
	hsdb.SetupHyperscan(paterns)
	ctx.hsdb.Updated = true

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
