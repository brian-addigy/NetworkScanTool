package main

import (
	"bytes"
	"encoding/json"
	"github.com/olekukonko/tablewriter"
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
)

type host struct {
	Brand   string `json:"manufacturer"`
	OsType  string `json:"os_type"`
	IpAddr  string `json:"ip_address"`
	MacAddr string `json:"mac_address"`
	Ports   string `json:"open_ports"`
	Hostname string `json:"hostname"`
}

const (
	version = "1.0"
)

func main() {
	var allHosts []host
	nmapPath := "/Library/Addigy/nmap"
	ipAddrs := GetIpAddress()
	jsonFlagPtr := flag.BoolP("json","j",false,"Sets out to json format")
	scanFlagPtr := flag.BoolP("scan", "s", false, "scans the network for hosts and their open Ports")
	versionFlagPtr := flag.BoolP("version", "v", false, "Displays currently version of Netscan")
	flag.Parse()

	if *versionFlagPtr {
		log.Printf("Netscan v%s\n", version)
		return
	}


	// --scan/-s isnt provided, print usage
	if !*scanFlagPtr {
		flag.Usage()
		return
	}

	// Checks if nmap; downloads if not
	_, pathErr := os.Stat(nmapPath)
	if pathErr != nil {
		log.Println("Nmap does not exist.")
		InstallNmap(nmapPath)
	}

	// Find local ip Address
	if ipAddrs != "error" {
		log.Println("Beginning Scan .....................\n")
		allHosts = ParseData(GetNmapData(nmapPath, ipAddrs))
		// flag is set
		if *jsonFlagPtr  {
			JsonPrintHosts(allHosts)
		} else {
			PrintHosts(allHosts)
		}
	}
}

func InstallNmap(nmapPath string) {
	url := "https://s3.amazonaws.com/files.addigy.com/nmap"
	log.Println("Now Installing nmap")

	// Create blank file
	out, createErr := os.Create(nmapPath)
	if createErr != nil {
		log.Println("Error creating file path: ", createErr)
	}
	defer out.Close()

	// Get the data
	resp, urlErr := http.Get(url)
	if urlErr != nil {
		log.Println("Error retreiving nmap: ", urlErr)
	}
	defer resp.Body.Close()

	// Write the data to file
	_, copyErr := io.Copy(out, resp.Body)
	if copyErr != nil {
		log.Println("Error installing nmap: ", copyErr)
	}

	// Make it executable
	exeCmd := exec.Command("chmod", "+x", nmapPath)
	runErr := exeCmd.Run()
	if runErr != nil {
		log.Println("Error running nmap: ", runErr)
	}

	log.Println("Done installing nmap")
}

func GetNmapData(nmapPath string,ip string) []string {
	//Runs nmap
	// 62078 iphone-sync; 64084 lan-cache
	scanPorts := "-p 22,445,62078,3389,64084,443,21,80,53,88,110,143,993,995,3283,5900,57621,60159,62078"

	output := exec.Command("nmap", "-PA",scanPorts, ip)
	var out bytes.Buffer
	output.Stdout = &out
	err := output.Run()
	// catch any errors when running command
	if err != nil {
		log.Fatal(err)
	}

	return strings.Split(out.String(),"\n")
}

func GetIpAddress() string {
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		log.Println(err)
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

func ParseHostname(hostname string) string {
	if hostname == "" {
		return "Unknown Hostname"
	}
	return hostname
}

func ParseData(data []string) []host {
	macAdrRegEx := regexp.MustCompile(`([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F])`)
	ipAdrRegEx := regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
	hostnameRegEx := regexp.MustCompile(`\s(.*?[.com])\s`)
	brandRegEx := regexp.MustCompile(`\((.*?)\)`)
	portRegEx := regexp.MustCompile(`(open)`)
	var allHosts []host
	var curHost host

	// iterate through entire data
	for i:=1; i < len(data); i++ {
		ipAdrs := ipAdrRegEx.FindString(data[i])
		hostname := hostnameRegEx.FindString(data[i])

		// iterate through 1 host
		// if scan reports <ipaddress>, then a new host has appeared
		if ipAdrs != "" && strings.Contains(data[i],"scan report"){
			// reuse host
			curHost = host{}
			curHost.IpAddr = ipAdrs
			curHost.Hostname = ParseHostname(hostname)
		}
		// Port header is found, port numbers follow
		if strings.Contains(data[i-1],"PORT") {
			// if i-1 contains port then the Ports are at i

			// iterate through all Ports, as long as you dont find end of port (contains "MAC" or a blank space))
			for data[i] != "" && !strings.Contains(data[i], "MAC") {
				portNum := strings.Split(data[i]," ")
				portSrv :=  portRegEx.FindString(data[i])
				// found a Regular exp. match
				if portSrv != ""  {
					if curHost.Ports == "" {
						curHost.Ports = portNum[0]
					} else {
						curHost.Ports = curHost.Ports + ", " + portNum[0]
					}
				}
				// Continue to iterate
				i++
			}
			// host ends with MAC address; except last host (current device)
			if strings.Contains(data[i],"MAC ") {
				mac := macAdrRegEx.FindString(data[i])
				brand := brandRegEx.FindString(data[i])
				curHost.MacAddr = mac
				curHost.Brand = strings.Trim(brand,"(")
				curHost.Brand = strings.Trim(curHost.Brand,")")
				curHost.OsType = GetOs(curHost.Ports,curHost.Brand)
				// add current host to the list of hosts
				allHosts = append(allHosts, curHost)
			}
		}
	}
	return allHosts
}

func GetOs(ports string, brand string) string {
	iosPort := "62078"

	if strings.Contains(brand, "Apple") {
		if strings.Contains(ports, iosPort) {
			return "iOS"
		} else {
			return "MacOS"
		}
	}
	return "Unknown"
}

func PrintHosts(allHosts []host) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Manufacturer","Hostname","MAC Address","IP Address","OS type","Open Ports"})
	table.SetBorder(false)                                // Set Border to false

	// print out each host
	for i:=0; i < len(allHosts); i++ {
		table.Append([]string{allHosts[i].Brand,allHosts[i].Hostname,allHosts[i].MacAddr, allHosts[i].IpAddr,allHosts[i].OsType,allHosts[i].Ports})
	}
	table.Render()
	log.Println("\nScan Complete.")
	log.Println("Total number of Hosts up:", len(allHosts))
}

func JsonPrintHosts(allHost []host) {
	// convert struct(s) to json format
	jsonHosts, _ := json.MarshalIndent(allHost, "", " ")
	// write out json to file
	log.Println(string(jsonHosts))
}