package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	flag "github.com/spf13/pflag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
)

type port struct {
	Number string
	State  string
}

type host struct {
	Brand   string
	OsType  string
	IpAddr  string
	MacAddr string
	Ports   []port
}

func main() {
	var allHosts []host
	nmapPath := "/Library/Addigy/nmap"
	ipAddrs := GetIpAddress()
	jsonFlagPtr := flag.BoolP("json","j",false,"Sets out to json format")
	scanFlagPtr := flag.BoolP("scan", "s", false, "scans the network for hosts and their open ports")
	flag.Parse()

	// Checks if nmap; downloads if not
	_, pathErr := os.Stat(nmapPath)
	if pathErr != nil {
		fmt.Println("File does not exist.")
		InstallNmap(nmapPath)
	}

	// --scan/-s isnt provided, print usage
	if !*scanFlagPtr {
		
	}

	if *scanFlagPtr {
		// Find local ip Address
		if ipAddrs != "error" {
			fmt.Println("Beginning Scan .....................")
			allHosts = ParseData(GetNmapData(nmapPath, ipAddrs))
			// flag is set
			if *jsonFlagPtr  {
				JsonPrintHosts(allHosts)
			} else {
				PrintHosts(allHosts)
			}
		}
	}
	fmt.Println("Done")
}

func InstallNmap(nmapPath string) {
	url := "https://s3.amazonaws.com/files.addigy.com/nmap"
	fmt.Println("Now Installing nmap")

	// Create blank file
	out, createErr := os.Create(nmapPath)
	if createErr != nil {
		fmt.Println("Error creating file path: ", createErr)
	}
	defer out.Close()

	// Get the data
	resp, urlErr := http.Get(url)
	if urlErr != nil {
		fmt.Println("Error retreiving nmap: ", urlErr)
	}
	defer resp.Body.Close()

	// Write the data to file
	_, copyErr := io.Copy(out, resp.Body)
	if copyErr != nil {
		fmt.Println("Error installing nmap: ", copyErr)
	}

	// Make it executable
	exeCmd := exec.Command("chmod", "+x", nmapPath)
	runErr := exeCmd.Run()
	if runErr != nil {
		fmt.Println("Error running nmap: ", runErr)
	}

	fmt.Println("Done installing nmap")
}

func GetNmapData(nmapPath string,ip string) []string {
	//Runs nmap
	scanPorts := "-p 22,3389,64084,443,21,80,53,88,110,143,993,995,3283,5900"

	output := exec.Command("nmap", "-PA",scanPorts, ip)
	var out bytes.Buffer
	output.Stdout = &out
	err := output.Run()
	if err != nil {
		log.Fatal(err)
	}

	return strings.Split(out.String(),"\n")
}

func GetIpAddress() string {
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		fmt.Println(err)
	}
	//Loop through network interfaces
	for _, address := range addrs {
		// check the address type and if it is not a loopback the display it
		// = GET LOCAL IP ADDRESS
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			//Local address usually start with 192.168.X.X
			if ipnet.IP.To4() != nil /*&& strings.Contains(ipnet.IP.String(), "192.168.")*/ {
				subMask, _ := ipnet.Mask.Size()
				return ipnet.IP.String() + "/" + strconv.Itoa(subMask)
			}
		}
	}

	return "error"
}

func ParseData(data []string) []host {
	macAdrReg := regexp.MustCompile(`([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])`)
	ipAdrReg := regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
	brandReg := regexp.MustCompile(`\((.*?)\)`)
	portReg := regexp.MustCompile(`(closed|open|filtered)`)
	var allHosts []host
	var curHost host

	// iterate through entire data
	for i:=1; i < len(data); i++ {
		ipAdrs := ipAdrReg.FindString(data[i])

		// iterate through 1 host, out gives ip address first
		// if IP is found, then a new host has appeared
		if ipAdrs != "" {
			// clear host to reuse
			curHost = host{}
			curHost.IpAddr = ipAdrs
		} else if strings.Contains(data[i-1],"PORT") {
			// if i-1 contains port then the Ports are at i

			// iterate through all Ports, as long as you dont find end of port (contains "MAC" or a blank space))
			for data[i] != "" && !strings.Contains(data[i], "MAC") {
				portNum := strings.Split(data[i]," ")
				portSrv :=  portReg.FindString(data[i])
				if portSrv != "" {
					tempPort := port{portNum[0],portSrv }
					curHost.Ports = append(curHost.Ports, tempPort)
				}
				// Continue to iterate
				i++
			}
			// host ends with MAC address; except last host (current device)
			if strings.Contains(data[i],"MAC ") {
				mac := macAdrReg.FindString(data[i])
				brand := brandReg.FindString(data[i])
				curHost.MacAddr = mac
				curHost.Brand = brand
			}
			// add current host to the list of hosts
			allHosts = append(allHosts, curHost)
		}
	}
	return allHosts
}

func PrintHosts(allHosts []host) {
	writer := new(tabwriter.Writer)
	writer.Init(os.Stdout, 0, 8, 2, '\t', tabwriter.Debug|tabwriter.AlignRight|tabwriter.TabIndent)
	fmt.Fprintln(writer, "Manufacturer\tMAC Address\tIP\tPorts\tState")

	for i:=0; i < len(allHosts); i++ {
		fmt.Fprintln(writer,"------------------------\t---------------------\t-----------------\t--------------\t---------")
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", allHosts[i].Brand,allHosts[i].MacAddr, allHosts[i].IpAddr,allHosts[i].Ports[0].Number,allHosts[i].Ports[0].State)
		for j:=1; j < len(allHosts[i].Ports); j++ {
			fmt.Fprintf(writer, " \t \t \t%s\t%s\n", allHosts[i].Ports[j].Number,allHosts[i].Ports[j].State)
		}
	}
	fmt.Fprintln(writer)
	writer.Flush()

}

func JsonPrintHosts(allHost []host) {
	// convert struct(s) to json format
	jsonHosts, _ := json.MarshalIndent(allHost, "", " ")
	// write out json to file
	fmt.Println(string(jsonHosts))
}