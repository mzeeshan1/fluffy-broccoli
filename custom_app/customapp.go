package main

import (
	"fmt"
	"unsafe"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

func main() {
	config := flow.Config{
		CPUList: "0-20",
	}
	flow.CheckFatal(flow.SystemInit(&config))

	rtpFlow, err4 := flow.SetReceiver(0)
	nonRtpFlow, err2 := flow.SetSeparator(rtpFlow, checkRTPPackets, nil)
	// err := flow.SetSenderFile(rtpFlow, "/root/zeeshan/rtp.pcap")
	err1 := flow.SetSender(nonRtpFlow, 0)
	err3 := flow.SetSender(rtpFlow, 2)
	fmt.Println(err4, err2, err1, err3)

	flow.CheckFatal(flow.SystemStart())

}

func checkRTPPackets(cur *packet.Packet, ctx flow.UserContext) bool {

	cur.ParseDataCheckVLAN()
	isUDP := isUDP(cur)
	if !isUDP { // its important that this is the first check because of layer 4 size calculations. It is assumed by default that packet is udp and not tcp
		// fmt.Println("packet is not RTP")
		return false
	}
	portCheck := portCheck(cur)
	version, payload := getVersionAndPayload(cur.Data)
	versionAndpayloadTypeCheck := versionAndPayloadTypeCheck(payload, version)
	lenCheck := lenCheck(cur)
	if !(versionAndpayloadTypeCheck && lenCheck && portCheck) {
		// fmt.Println("Packet is not RTP")
		return false
	}

	// fmt.Println("version and payload type check: ", versionAndpayloadTypeCheck, "lenCheck", lenCheck, "port check: ", portCheck)

	// fmt.Println("version: ", version, "payload: ", payload, "is udp: ", isUDP, "portCheck: ", portCheck, " payload type check: ", payloadTypeCheck, s)
	// fmt.Println("packet is RTP")
	return true

}

func getVersionAndPayload(ptr unsafe.Pointer) (uint8, uint8) {
	v := *((*uint8)(unsafe.Pointer(uintptr(ptr) + uintptr(0))))
	p := *((*uint8)(unsafe.Pointer(uintptr(ptr) + uintptr(1))))
	return v >> 6, p & 127
}

func isUDP(cur *packet.Packet) bool {
	if cur.L4 == nil {
		return false
	}
	IPHdr := (*packet.IPv4Hdr)(cur.L3)
	if IPHdr.NextProtoID == 17 {
		return true
	}
	return false
}

func portCheck(cur *packet.Packet) bool {
	frag := fragmentCheck(cur)
	if !frag {
		return false
	}

	UDPHdr := (*packet.UDPHdr)(cur.L4)
	srcPort := SwapBytesUint16(UDPHdr.SrcPort)
	dstPort := SwapBytesUint16(UDPHdr.DstPort)
	if srcPort < 1024 || dstPort < 1024 {
		return false
	}
	evenCheck := portsEven(srcPort, dstPort)
	// fmt.Println("even Check: ", evenCheck)
	// fmt.Println("src port: ", srcPort, "dst port: ", dstPort)
	return evenCheck
}

func fragmentCheck(cur *packet.Packet) bool {
	IPHdr := (*packet.IPv4Hdr)(cur.L3)
	if (IPHdr.FragmentOffset & 16383) != 0 { //and with 0011 1111 1111 1111 to remove reserved and dont fragment flag from ip header
		return false
	}
	return true //passed fragment check
}

func SwapBytesUint16(x uint16) uint16 {
	return x<<8 | x>>8
}

func portsEven(srcPort uint16, dstPort uint16) bool {
	if srcPort%2 == 0 && dstPort%2 == 0 {
		return true
	}
	return false
}

func versionAndPayloadTypeCheck(payload uint8, version uint8) bool {
	// fmt.Println("payload: ", payload)
	if ((payload >= 1 && payload <= 31) || (payload >= 96 && payload <= 127)) && version == 2 {
		return true
	}
	return false
}
func lenCheck(cur *packet.Packet) bool {
	var vlanLength uint
	var IPHdr packet.IPv4Hdr
	pktLen := cur.GetPacketSegmentLen()
	VLANHdr := cur.GetVLAN()
	if VLANHdr != nil {
		vlanLength = 4
	}
	payLoadLength := pktLen - vlanLength - 18 - (uint)(unsafe.Sizeof(IPHdr)) - 8 // 18 for ethernet and 8 for udp
	if payLoadLength < 12 || payLoadLength > 400 {
		return false
	}
	return true
}
