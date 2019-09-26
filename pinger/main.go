package main

import (
	"fmt"
	"time"

	"github.com/sparrc/go-ping"
)

func main() {
	links := []string{"172.30.235.1", "172.30.233.1", "172.30.231.1", "172.30.229.1", "172.30.227.1", "172.30.225.1", "172.30.223.1", "172.30.221.1", "172.30.219.1", "172.30.217.1", "172.30.213.1"}
	c := make(chan string)
	for _, l := range links {
		go checkLink(l, c)
	}

	for l := range c {
		go checkLink(l, c)
	}
	// pingCheck("192.168.3.44")
}

func checkLink(ip string, c chan string) {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		panic(err)
	}
	pinger.Count = 5
	pinger.Timeout = time.Second * 5

	pinger.OnRecv = func(pkt *ping.Packet) {
		// fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
		// pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		// fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
		// fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
		// stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		if stats.PacketLoss == 100 {
			fmt.Println(ip, "is down")
			c <- ip
			return
		}
		c <- ip
		fmt.Println(ip, "is up")
		// fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
		// stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
	}

	// fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
	pinger.Run()
}
