// Package main provides a comprehensive tool for analyzing PCAP files, extracting various network metrics,
// and summarizing the results in a detailed analysis report. The tool also supports zipping the generated
// analysis files and deleting the original files after they are added to the zip.

package main

import (
	"archive/zip"
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sqweek/dialog"
)

// tcpConnectionKey represents a unique TCP connection based on source and destination IPs and ports.
type tcpConnectionKey struct {
	srcIP   string
	dstIP   string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
}

// tcpConnectionData holds details of a TCP connection, including retransmissions and sequence numbers.
type tcpConnectionData struct {
	srcPort         layers.TCPPort
	dstPort         layers.TCPPort
	sequenceNumbers map[uint32]int
	retransmissions int // Count retransmissions
}

// packetDetail stores information about individual packets.
type packetDetail struct {
	timestamp        time.Time
	seqNum           uint32
	ackNum           uint32
	interArrivalTime time.Duration
	length           int
	windowSize       uint16
	fragmentOffset   uint16
	moreFragments    bool
	srcPort          layers.TCPPort
	dstPort          layers.TCPPort
}

// tcpSessionKey represents a unique TCP session based on source and destination IPs and ports.
type tcpSessionKey struct {
	srcIP   string
	dstIP   string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
}

// latencyInfo stores latency information between two hosts.
type latencyInfo struct {
	srcIP   string
	dstIP   string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
	latency time.Duration
}

// latencyCategory categorizes latency data into three categories.
type latencyCategory struct {
	below60ms         int
	between60And100ms int
	above100ms        int
	total             int
}

// handshakeFailureInfo holds information about handshake failures.
type handshakeFailureInfo struct {
	identifier string
	count      int
	dstPort    layers.TCPPort
}

// connectionBreakInfo holds information about connection breaks.
type connectionBreakInfo struct {
	identifier string
	count      int
	dstPort    layers.TCPPort
}

// rttInfo stores round-trip time information between two hosts.
type rttInfo struct {
	srcIP string
	dstIP string
	rtt   time.Duration
}

// dnsQuery represents a DNS query with its timestamp and ID.
type dnsQuery struct {
	timestamp time.Time
	id        uint16
	query     string
}

// dnsResponse represents a DNS response with its timestamp and ID.
type dnsResponse struct {
	timestamp time.Time
	id        uint16
	response  string
}

// dnsDelayInfo stores information about DNS query-response delay.
type dnsDelayInfo struct {
	query     string
	srcIP     string
	dstIP     string
	queryTime time.Time
	respTime  time.Time
	delay     time.Duration
}

// errorMessage represents an error message detected in the traffic.
type errorMessage struct {
	srcIP     string
	dstIP     string
	errorType string
	count     int
}

// jitterInfo holds information about the jitter in packet arrivals.
type jitterInfo struct {
	identifier string
	srcPort    layers.TCPPort
	dstPort    layers.TCPPort
	avgJitter  time.Duration
}

// throughputInfo stores throughput information between two hosts.
type throughputInfo struct {
	identifier string
	srcPort    layers.TCPPort
	dstPort    layers.TCPPort
	throughput float64 // in bytes per second
}

// duplicateAckInfo holds information about duplicate ACKs detected.
type duplicateAckInfo struct {
	identifier string
	srcPort    layers.TCPPort
	dstPort    layers.TCPPort
	dupAcks    int
}

// windowSizeInfo holds information about TCP window sizes.
type windowSizeInfo struct {
	identifier      string
	srcPort         layers.TCPPort
	dstPort         layers.TCPPort
	minSize         uint16
	maxSize         uint16
	avgSize         float64
	delta           float64
	deltaPercentage float64
}

// fragmentationInfo stores information about packet fragmentation.
type fragmentationInfo struct {
	identifier    string
	srcPort       layers.TCPPort
	dstPort       layers.TCPPort
	fragmentCount int
}

// Global variables to hold various metrics and data.
var dnsQueries = make(map[uint16]dnsQuery)
var dnsDelays = []dnsDelayInfo{}
var errorMessages = make(map[string]map[string]int)
var tcpConnections = make(map[string]*tcpConnectionData)
var sessions = make(map[string][]packetDetail)
var latencyData = []latencyInfo{}
var latencyCategories = make(map[string]*latencyCategory)
var handshakeFailures = make(map[string]int)
var connectionBreaks = make(map[string]int)
var rttData = []rttInfo{}
var jitterData = []jitterInfo{}
var throughputData = []throughputInfo{}
var duplicateAcks = []duplicateAckInfo{}
var windowSizes = []windowSizeInfo{}
var fragmentationData = []fragmentationInfo{}
var suspectScores = make(map[string]int)
var metricContributions = make(map[string]map[string]int)
var rawMetrics = make(map[string]map[string]interface{})


// main is the entry point of the application. It sets up logging, opens a file selection dialog,
// processes the selected PCAP file, writes various analysis results to files, and generates a summary report.
func main() {
	// Open output.log file
	logFile, err := os.OpenFile("output.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	// Redirect stdout and stderr to log file
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)
	os.Stdout = logFile
	os.Stderr = logFile

	// Open file selection dialog
	selectedFile, err := dialog.File().Filter("PCAP files", "pcap").Title("Select a PCAP file").Load()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Analyzing the selected pcap file: %s\n", selectedFile)
	timestamp := time.Now().Format("20060102_150405")

	// Process the selected PCAP file for transactions
	handlePcapTrns(selectedFile)
	
	// Process the selected PCAP file for latency
	handlePcapLat(selectedFile)

	// Write retransmission data to a file with a timestamp
	writeRetransmissionTable(timestamp)
	
	// Write latency percentages to a file with a timestamp
	writeLatencyPercentages(timestamp)
	
	// Write handshake failures and connection breaks to a file
	writeHandshakeFailuresAndConnectionBreaks(timestamp)
	
	// Write RTT data to a file with a timestamp
	writeRTTData(timestamp)
	
	// Calculate and write jitter to a file with a timestamp
	calculateJitter(timestamp)
	
	// Calculate and write throughput to a file with a timestamp
	calculateThroughput(timestamp)
	
	// Calculate and write duplicate ACKs to a file with a timestamp
	calculateDuplicateAcks(timestamp)
	
	// Calculate and write window size statistics to a file with a timestamp
	calculateWindowSizeStatistics(timestamp)
	
	// Calculate and write fragmentation statistics to a file with a timestamp
	calculateFragmentationStatistics(timestamp)
	
	// Calculate and write DNS resolution delays to a file with a timestamp
	calculateDNSResolutionDelays(timestamp)
	
	// Calculate and write error message counts to a file with a timestamp
	calculateErrorMessageCounts(timestamp)
	
	// Analyze the results and write the summary
	analyzeResults(timestamp)

	// Prompt to keep the terminal open
	log.Println("Press 'Enter' to exit...")
	fmt.Scanln() // Wait for the user to press 'Enter'
}


// generateIdentifier creates a unique identifier for a TCP connection based on the source and destination IP addresses.
// This identifier is used to uniquely identify a connection in the analysis.
//
// Parameters:
// - srcIP: The source IP address of the connection.
// - dstIP: The destination IP address of the connection.
//
// Returns:
// A string in the format "srcIP_dstIP" which uniquely identifies the connection.
func generateIdentifier(srcIP, dstIP string) string {
	return fmt.Sprintf("%s_%s", srcIP, dstIP)
}


// generateIdentifier creates a unique identifier for a TCP connection based on the source and destination IP addresses.
// This identifier is used to uniquely identify a connection in the analysis.
//
// Parameters:
// - srcIP: The source IP address of the connection.
// - dstIP: The destination IP address of the connection.
//
// Returns:
// A string in the format "srcIP_dstIP" which uniquely identifies the connection.
func generateIdentifier(srcIP, dstIP string) string {
	return fmt.Sprintf("%s_%s", srcIP, dstIP)
}


// isValidIP checks if the given string is a valid IP address.
//
// Parameters:
// - ip: The string to check.
//
// Returns:
// A boolean value indicating whether the string is a valid IP address.
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}


// handlePcapTrns processes the given PCAP file for transaction analysis.
// It opens the PCAP file, reads the packets, and processes each packet for various metrics.
//
// Parameters:
// - filePath: The path to the PCAP file to process.
func handlePcapTrns(filePath string) {
	fmt.Println("Starting transaction analysis...")
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
		detectHandshakeFailuresAndConnectionBreaks(packet)
		processRTT(packet)
	}
	fmt.Println("Completed transaction analysis.")
}


// processPacket processes an individual packet for TCP connection data.
// It updates the retransmission count for the connection based on sequence numbers.
//
// Parameters:
// - packet: The packet to process.
func processPacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return
		}
		ip, _ := ipLayer.(*layers.IPv4)

		identifier := generateIdentifier(ip.SrcIP.String(), ip.DstIP.String())

		data, exists := tcpConnections[identifier]
		if !exists {
			data = &tcpConnectionData{
				sequenceNumbers: make(map[uint32]int),
			}
			tcpConnections[identifier] = data
		}

		data.sequenceNumbers[tcp.Seq]++
		if data.sequenceNumbers[tcp.Seq] > 1 {
			data.retransmissions++
		}
	}
}


// writeRetransmissionTable writes the retransmission data to a file with a timestamp.
// It creates a new file named "retransmissions_<timestamp>.txt" and writes the TCP connections
// with their retransmission counts in a tabular format.
//
// Parameters:
// - timestamp: A string representing the current timestamp to be included in the filename.
func writeRetransmissionTable(timestamp string) {
	fmt.Println("Writing retransmission table...")
	filePath := fmt.Sprintf("retransmissions_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	// connectionInfo stores the details of each TCP connection including retransmissions
	type connectionInfo struct {
		identifier string
		srcPort    layers.TCPPort
		dstPort    layers.TCPPort
		retrans    int
	}

	// connections stores all the TCP connections with retransmissions
	var connections []connectionInfo
	for identifier, data := range tcpConnections {
		if data.retransmissions > 0 {
			connections = append(connections, connectionInfo{
				identifier: identifier,
				srcPort:    data.srcPort,
				dstPort:    data.dstPort,
				retrans:    data.retransmissions,
			})
		}
	}

	// Sort connections by retransmission count in descending order
	sort.Slice(connections, func(i, j int) bool {
		return connections[i].retrans > connections[j].retrans
	})

	// Write the retransmission data to the file
	fmt.Fprintln(file, "Source_Destination\tSource Port\tDestination Port\tRetransmissions")
	for _, conn := range connections {
		fmt.Fprintf(file, "%s\t%d\t\t%d\t\t\t%d\n", conn.identifier, conn.srcPort, conn.dstPort, conn.retrans)
	}
	fmt.Println("Retransmission table written.")
}

// handlePcapLat processes a PCAP file to analyze latency, handshake failures, and connection breaks.
// It reads the file, processes each packet, and calls specific functions to handle different aspects of the analysis.
//
// Parameters:
// - filePath: The path to the PCAP file to be processed.
func handlePcapLat(filePath string) {
	fmt.Println("Starting latency analysis...")
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacketLat(packet)
		detectHandshakeFailuresAndConnectionBreaks(packet)
		processRTT(packet)
	}
	fmt.Println("Completed latency analysis.")
}


// processPacketLat processes individual packets to analyze latency and categorize them.
// It handles different types of packets (UDP, ICMP, TCP) and extracts relevant information.
//
// Parameters:
// - packet: The packet to be processed.
func processPacketLat(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return // Not an IPv4 packet
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Generate uniform identifier
	identifier := generateIdentifier(ip.SrcIP.String(), ip.DstIP.String())

	// Process UDP DNS packets
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		if udp.SrcPort == 53 || udp.DstPort == 53 {
			// This is a DNS packet
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				if dns.QR == false {
					// This is a DNS query
					if len(dns.Questions) > 0 {
						query := dns.Questions[0].Name
						dnsQueries[dns.ID] = dnsQuery{
							timestamp: packet.Metadata().Timestamp,
							id:        dns.ID,
							query:     string(query),
						}
					}
				} else {
					// This is a DNS response
					if len(dns.Answers) > 0 {
						if query, found := dnsQueries[dns.ID]; found {
							delay := packet.Metadata().Timestamp.Sub(query.timestamp)
							dnsDelays = append(dnsDelays, dnsDelayInfo{
								query:     query.query,
								srcIP:     ip.SrcIP.String(),
								dstIP:     ip.DstIP.String(),
								queryTime: query.timestamp,
								respTime:  packet.Metadata().Timestamp,
								delay:     delay,
							})
							delete(dnsQueries, dns.ID) // Remove the matched query
						}
					}
				}
			}
		}
	}

	// Process ICMP packets
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		errorType := getICMPTypeString(icmp.TypeCode)
		if _, ok := errorMessages[identifier]; !ok {
			errorMessages[identifier] = make(map[string]int)
		}
		errorMessages[identifier][errorType]++
	}

	// Process TCP packets
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.RST {
			errorType := "TCP_RST"
			if _, ok := errorMessages[identifier]; !ok {
				errorMessages[identifier] = make(map[string]int)
			}
			errorMessages[identifier][errorType]++
		}

		detail := packetDetail{
			timestamp:      packet.Metadata().Timestamp,
			seqNum:         tcp.Seq,
			ackNum:         tcp.Ack,
			length:         len(packet.Data()),
			windowSize:     tcp.Window,
			fragmentOffset: ip.FragOffset,
			moreFragments:  ip.Flags&layers.IPv4MoreFragments != 0,
			srcPort:        tcp.SrcPort,
			dstPort:        tcp.DstPort,
		}

		// Calculate inter-arrival time
		if len(sessions[identifier]) > 0 {
			lastPacket := sessions[identifier][len(sessions[identifier])-1]
			detail.interArrivalTime = detail.timestamp.Sub(lastPacket.timestamp)
		}

		sessions[identifier] = append(sessions[identifier], detail)

		reverseIdentifier := generateIdentifier(ip.DstIP.String(), ip.SrcIP.String())
		if responses, found := sessions[reverseIdentifier]; found {
			for _, resp := range responses {
				if resp.seqNum == tcp.Ack {
					latency := packet.Metadata().Timestamp.Sub(resp.timestamp)
					latencyData = append(latencyData, latencyInfo{
						srcIP:   ip.SrcIP.String(),
						dstIP:   ip.DstIP.String(),
						srcPort: tcp.SrcPort,
						dstPort: tcp.DstPort,
						latency: latency,
					})
					categorizeLatency(identifier, latency)
				}
			}
		}

		if !tcp.FIN && !tcp.RST {
			sessions[identifier] = append(sessions[identifier], detail)
		}
	}
}
}

// getICMPTypeString returns a string representation of the ICMP type based on the provided ICMPv4TypeCode.
// It translates common ICMP types into human-readable strings for logging and reporting purposes.
//
// Parameters:
// - typeCode: The ICMPv4TypeCode representing the type and code of the ICMP message.
//
// Returns:
// - A string describing the ICMP type and code.
func getICMPTypeString(typeCode layers.ICMPv4TypeCode) string {
	switch typeCode.Type() {
	case layers.ICMPv4TypeDestinationUnreachable:
		return "Destination Unreachable"
	case layers.ICMPv4TypeTimeExceeded:
		return "Time Exceeded"
	case layers.ICMPv4TypeParameterProblem:
		return "Parameter Problem"
	case layers.ICMPv4TypeRedirect:
		return "Redirect"
	case layers.ICMPv4TypeEchoRequest:
		return "Echo Request"
	case layers.ICMPv4TypeEchoReply:
		return "Echo Reply"
	case layers.ICMPv4TypeSourceQuench:
		return "Source Quench"
	default:
		return fmt.Sprintf("Type %d Code %d", typeCode.Type(), typeCode.Code())
	}
}


// categorizeLatency categorizes the given latency into predefined buckets and updates the latency categories map.
//
// Parameters:
// - identifier: A unique identifier for the connection (usually a combination of source and destination IPs).
// - latency: The latency duration to be categorized.
func categorizeLatency(identifier string, latency time.Duration) {
	category, exists := latencyCategories[identifier]
	if !exists {
		category = &latencyCategory{}
		latencyCategories[identifier] = category
	}
	category.total++
	switch {
	case latency < 60*time.Millisecond:
		category.below60ms++
	case latency >= 60*time.Millisecond && latency < 100*time.Millisecond:
		category.between60And100ms++
	default:
		category.above100ms++
	}
}


// writeLatencyPercentages calculates and writes latency percentages to a file.
// It processes the categorized latency data, calculates the percentages for each category, and writes the results to a file.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func writeLatencyPercentages(timestamp string) {
	fmt.Println("Writing latency percentages...")
	filePath := fmt.Sprintf("latency_percentages_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	type latencyPercentage struct {
		identifier string
		category   string
		percentage float64
	}

	var percentages []latencyPercentage
	for identifier, category := range latencyCategories {
		if category.total > 0 {
			percentages = append(percentages, latencyPercentage{
				identifier: identifier,
				category:   "<60ms",
				percentage: float64(category.below60ms) / float64(category.total) * 100,
			})
			percentages = append(percentages, latencyPercentage{
				identifier: identifier,
				category:   "60ms-100ms",
				percentage: float64(category.between60And100ms) / float.float64(category.total) * 100,
			})
			percentages = append(percentages, latencyPercentage{
				identifier: identifier,
				category:   ">100ms",
				percentage: float.float64(category.above100ms) / float.float64(category.total) * 100,
			})
		}
	}

	// Sort the percentages as specified
	// Define the order of categories
	categoryOrder := map[string]int{
		">100ms": 0,
		"60ms-100ms": 1,
		"<60ms": 2,
	}

	sort.Slice(percentages, func(i, j int) bool {
		if percentages[i].percentage == 0 && percentages[j].percentage != 0 {
			return false
		}
		if percentages[i].percentage != 0 && percentages[j].percentage == 0 {
			return true
		}
		if percentages[i].percentage == 0 && percentages[j].percentage == 0 {
			return false
		}
		// Sort by category order first, then by percentage
		if categoryOrder[percentages[i].category] != categoryOrder[percentages[j].category] {
			return categoryOrder[percentages[i].category] < categoryOrder[percentages[j].category]
		}
		return percentages[i].percentage > percentages[j].percentage
	})

	// Write the sorted data to the file
	fmt.Fprintln(file, "Source_Destination\tLatency Category\tPercentage")
	for _, p := range percentages {
		if p.percentage > 0 {
			fmt.Fprintf(file, "%s\t%s\t\t\t%.2f%%\n", p.identifier, p.category, p.percentage)
		}
	}
	fmt.Println("Latency percentages written.")
}


// writeHandshakeFailuresAndConnectionBreaks writes handshake failures and connection breaks to a file.
// It processes the collected handshake failures and connection breaks, sorts them, and writes the results to a file.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func writeHandshakeFailuresAndConnectionBreaks(timestamp string) {
	fmt.Println("Writing handshake failures and connection breaks...")
	filePath := fmt.Sprintf("handshake_failures_and_connection_breaks_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	type handshakeFailureInfo struct {
		identifier string
		count      int
	}

	type connectionBreakInfo struct {
		identifier string
		count      int
	}

	// Collect and sort handshake failures
	var handshakeFailuresList []handshakeFailureInfo
	for identifier, count := range handshakeFailures {
		handshakeFailuresList = append(handshakeFailuresList, handshakeFailureInfo{
			identifier: identifier,
			count:      count,
		})
	}
	sort.Slice(handshakeFailuresList, func(i, j int) bool {
		return handshakeFailuresList[i].count > handshakeFailuresList[j].count
	})

	// Collect and sort connection breaks
	var connectionBreaksList []connectionBreakInfo
	for identifier, count := range connectionBreaks {
		connectionBreaksList = append(connectionBreaksList, connectionBreakInfo{
			identifier: identifier,
			count:      count,
		})
	}
	sort.Slice(connectionBreaksList, func(i, j int) bool {
		return connectionBreaksList[i].count > connectionBreaksList[j].count
	})

	// Write handshake failures to the file
	fmt.Fprintln(file, "Handshake Failures")
	for _, failure := range handshakeFailuresList {
		fmt.Fprintf(file, "Handshake failure between %s %d failures\n", failure.identifier, failure.count)
	}

	// Write connection breaks to the file
	fmt.Fprintln(file, "\nConnection Breaks")
	for _, breakInfo := range connectionBreaksList {
		fmt.Fprintf(file, "Connection break between %s %d breaks\n", breakInfo.identifier, breakInfo.count)
	}
	fmt.Println("Handshake failures and connection breaks written.")
}


// detectHandshakeFailuresAndConnectionBreaks detects and logs handshake failures and connection breaks from TCP packets.
// It analyzes the TCP flags to identify failed handshakes and broken connections, updating the relevant counters.
//
// Parameters:
// - packet: The packet to analyze.
func detectHandshakeFailuresAndConnectionBreaks(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return // Not a TCP packet
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return // Not an IPv4 packet
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// Ignore packets with both source and destination ports > 1023
	if tcp.SrcPort > 1023 && tcp.DstPort > 1023 {
		return
	}

	identifier := generateIdentifier(ip.SrcIP.String(), ip.DstIP.String())

	// Detect SYN packets (start of a handshake)
	if tcp.SYN && !tcp.ACK {
		sessions[identifier] = append(sessions[identifier], packetDetail{timestamp: packet.Metadata().Timestamp, seqNum: tcp.Seq})
	} else if tcp.SYN && tcp.ACK {
		// Detect SYN-ACK packets (response in a handshake)
		if details, found := sessions[identifier]; found {
			for _, detail := range details {
				if detail.seqNum == tcp.Seq-1 {
					return // Handshake is successful, no failure
				}
			}
		}
		handshakeFailures[identifier]++
	} else if tcp.RST || tcp.FIN {
		// Detect connection breaks (RST or FIN packets)
		connectionBreaks[identifier]++
	}
}

// processRTT processes Round Trip Time (RTT) information from a given packet.
// It extracts the relevant details from the packet, calculates the RTT for TCP handshakes, and logs the RTT data.
//
// Parameters:
// - packet: The packet to analyze.
func processRTT(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return // Not a TCP packet
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return // Not an IPv4 packet
	}
	ip, _ := ipLayer.(*layers.IPv4)

	identifier := generateIdentifier(ip.SrcIP.String(), ip.DstIP.String())

	detail := packetDetail{
		timestamp: packet.Metadata().Timestamp,
		seqNum:    tcp.Seq,
		ackNum:    tcp.Ack,
		srcPort:   tcp.SrcPort,
		dstPort:   tcp.DstPort,
	}

	// Handle SYN packets (start of a handshake)
	if tcp.SYN && !tcp.ACK {
		sessions[identifier] = append(sessions[identifier], detail)
	} else if tcp.SYN && tcp.ACK {
		// Handle SYN-ACK packets (response in a handshake)
		if requests, found := sessions[identifier]; found {
			for _, req := range requests {
				if req.seqNum == tcp.Ack-1 {
					rtt := packet.Metadata().Timestamp.Sub(req.timestamp)
					rttData = append(rttData, rttInfo{
						srcIP: ip.SrcIP.String(),
						dstIP: ip.DstIP.String(),
						rtt:   rtt,
					})
					return
				}
			}
		}
	} else {
		// Handle other packets to measure RTT
		reverseIdentifier := generateIdentifier(ip.DstIP.String(), ip.SrcIP.String())
		if requests, found := sessions[reverseIdentifier]; found {
			for _, req := range requests {
				if req.seqNum+1 == tcp.Ack {
					rtt := packet.Metadata().Timestamp.Sub(req.timestamp)
					rttData = append(rttData, rttInfo{
						srcIP: ip.DstIP.String(),
						dstIP: ip.SrcIP.String(),
						rtt:   rtt,
					})
					return
				}
			}
		}
	}
}

// writeRTTData writes the collected RTT data to a file.
// It sorts the RTT data in descending order and writes the results to a file.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func writeRTTData(timestamp string) {
	fmt.Println("Writing RTT data...")
	filePath := fmt.Sprintf("rtt_data_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	// Sort RTT data in descending order
	sort.Slice(rttData, func(i, j int) bool {
		return rttData[i].rtt > rttData[j].rtt
	})

	// Write RTT data to the file
	fmt.Fprintln(file, "Source_Destination\tRTT")
	for _, data := range rttData {
		identifier := generateIdentifier(data.srcIP, data.dstIP)
		fmt.Fprintf(file, "%s\t%s\n", identifier, data.rtt)
	}
	fmt.Println("RTT data written.")
}


// calculateJitter calculates the average jitter for each connection and writes the results to a file.
// It processes packet data to compute the inter-arrival time jitter and stores the results.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func calculateJitter(timestamp string) {
	fmt.Println("Calculating jitter...")
	filePath := fmt.Sprintf("jitter_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	var jitterData []jitterInfo

	for identifier, packets := range sessions {
		var totalJitter time.Duration
		var count int

		for i := 1; i < len(packets); i++ {
			jitter := packets[i].interArrivalTime - packets[i-1].interArrivalTime
			if jitter < 0 {
				jitter = -jitter
			}
			totalJitter += jitter
			count++
		}

		if count > 0 {
			avgJitter := totalJitter / time.Duration(count)
			jitterData = append(jitterData, jitterInfo{
				identifier: identifier,
				srcPort:    packets[0].srcPort,
				dstPort:    packets[0].dstPort,
				avgJitter:  avgJitter,
			})
		}
	}

	// Sort jitter data by average jitter in descending order
	sort.Slice(jitterData, func(i, j int) bool {
		return jitterData[i].avgJitter > jitterData[j].avgJitter
	})

	// Write jitter data to file
	fmt.Fprintln(file, "Source_Destination\tSource Port\tDestination Port\tAverage Jitter")
	for _, data := range jitterData {
		fmt.Fprintf(file, "%s\t%d\t\t%d\t\t\t%s\n", data.identifier, data.srcPort, data.dstPort, data.avgJitter)
	}
	fmt.Println("Jitter calculation completed.")
}


// calculateThroughput calculates the throughput for each connection and writes the results to a file.
// It processes packet data to compute the throughput in bytes per second and stores the results.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func calculateThroughput(timestamp string) {
	fmt.Println("Calculating throughput...")
	filePath := fmt.Sprintf("throughput_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	var throughputData []throughputInfo

	for identifier, packets := range sessions {
		if len(packets) < 2 {
			continue // Not enough data to calculate throughput
		}

		var totalData int
		var totalTime time.Duration

		for i := 1; i < len(packets); i++ {
			totalData += packets[i].length
			totalTime = packets[i].timestamp.Sub(packets[0].timestamp)
		}

		if totalTime > 0 {
			throughput := float64(totalData) / totalTime.Seconds()
			throughputData = append(throughputData, throughputInfo{
				identifier: identifier,
				srcPort:    packets[0].srcPort,
				dstPort:    packets[0].dstPort,
				throughput: throughput,
			})
		}
	}

	// Sort throughput data by throughput in descending order
	sort.Slice(throughputData, func(i, j int) bool {
		return throughputData[i].throughput > throughputData[j].throughput
	})

	// Write throughput data to file
	fmt.Fprintln(file, "Source_Destination\tSource Port\tDestination Port\tThroughput (Bps)")
	for _, data := range throughputData {
		fmt.Fprintf(file, "%s\t%d\t\t%d\t\t\t%.2f\n", data.identifier, data.srcPort, data.dstPort, data.throughput)
	}
	fmt.Println("Throughput calculation completed.")
}


// calculateDuplicateAcks calculates the number of duplicate ACKs for each connection and writes the results to a file.
// It processes packet data to count duplicate acknowledgments and stores the results.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func calculateDuplicateAcks(timestamp string) {
	fmt.Println("Calculating duplicate ACKs...")
	filePath := fmt.Sprintf("duplicate_acks_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	var dupAckData []duplicateAckInfo

	for identifier, packets := range sessions {
		ackCounts := make(map[uint32]int)
		duplicateAcks := 0

		for _, packet := range packets {
			if packet.ackNum != 0 {
				ackCounts[packet.ackNum]++
				if ackCounts[packet.ackNum] > 1 {
					duplicateAcks++
				}
			}
		}

		if duplicateAcks > 0 {
			dupAckData = append(dupAckData, duplicateAckInfo{
				identifier: identifier,
				srcPort:    packets[0].srcPort,
				dstPort:    packets[0].dstPort,
				dupAcks:    duplicateAcks,
			})
		}
	}

	// Sort duplicate ACK data by the number of duplicate ACKs in descending order
	sort.Slice(dupAckData, func(i, j int) bool {
		return dupAckData[i].dupAcks > dupAckData[j].dupAcks
	})

	// Write duplicate ACK data to file
	fmt.Fprintln(file, "Source_Destination\tSource Port\tDestination Port\tDuplicate ACKs")
	for _, data := range dupAckData {
		fmt.Fprintf(file, "%s\t%d\t\t%d\t\t\t%d\n", data.identifier, data.srcPort, data.dstPort, data.dupAcks)
	}
	fmt.Println("Duplicate ACK calculation completed.")
}


// calculateWindowSizeStatistics calculates window size statistics for each connection and writes the results to a file.
// It processes packet data to compute the minimum, maximum, and average window sizes, as well as the delta and delta percentage.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func calculateWindowSizeStatistics(timestamp string) {
	fmt.Println("Calculating window size statistics...")
	filePath := fmt.Sprintf("window_size_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	var windowSizeData []windowSizeInfo

	for identifier, packets := range sessions {
		if len(packets) == 0 {
			continue
		}

		var totalSize uint32
		minSize := packets[0].windowSize
		maxSize := packets[0].windowSize

		for _, packet := range packets {
			totalSize += uint32(packet.windowSize)
			if packet.windowSize < minSize {
				minSize = packet.windowSize
			}
			if packet.windowSize > maxSize {
				maxSize = packet.windowSize
			}
		}

		avgSize := float64(totalSize) / float64(len(packets))
		delta := float64(maxSize) - avgSize
		deltaPercentage := (delta / avgSize) * 100

		windowSizeData = append(windowSizeData, windowSizeInfo{
			identifier:      identifier,
			srcPort:         packets[0].srcPort,
			dstPort:         packets[0].dstPort,
			minSize:         minSize,
			maxSize:         maxSize,
			avgSize:         avgSize,
			delta:           delta,
			deltaPercentage: deltaPercentage,
		})
	}

	// Sort window size data by average size in descending order
	sort.Slice(windowSizeData, func(i, j int) bool {
		return windowSizeData[i].avgSize > windowSizeData[j].avgSize
	})

	// Write window size data to file
	fmt.Fprintln(file, "Source_Destination\tSource Port\tDestination Port\tMin Window Size\tMax Window Size\tAvg Window Size\tDelta\tDelta Percentage")
	for _, data := range windowSizeData {
		fmt.Fprintf(file, "%s\t%d\t\t%d\t\t\t%d\t\t%d\t\t%.2f\t%.2f\t%.2f%%\n", data.identifier, data.srcPort, data.dstPort, data.minSize, data.maxSize, data.avgSize, data.delta, data.deltaPercentage)
	}
	fmt.Println("Window size statistics calculation completed.")
}

// calculateFragmentationStatistics calculates the number of fragmented packets for each connection
// and writes the results to a file. It processes packet data to count fragments and stores the results.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func calculateFragmentationStatistics(timestamp string) {
	fmt.Println("Calculating fragmentation statistics...")
	filePath := fmt.Sprintf("fragmentation_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	var fragmentationData []fragmentationInfo

	for identifier, packets := range sessions {
		fragmentCount := 0

		for _, packet := range packets {
			if packet.fragmentOffset > 0 || packet.moreFragments {
				fmt.Printf("Fragment found: %+v\n", packet) // Debug logging
				fragmentCount++
			}
		}

		if fragmentCount > 0 {
			fragmentationData = append(fragmentationData, fragmentationInfo{
				identifier:    identifier,
				srcPort:       packets[0].srcPort,
				dstPort:       packets[0].dstPort,
				fragmentCount: fragmentCount,
			})
		}
	}

	// Sort fragmentation data by fragment count in descending order
	sort.Slice(fragmentationData, func(i, j int) bool {
		return fragmentationData[i].fragmentCount > fragmentationData[j].fragmentCount
	})

	// Write fragmentation data to file
	fmt.Fprintln(file, "Source_Destination\tSource Port\tDestination Port\tFragment Count")
	if len(fragmentationData) == 0 {
		fmt.Fprintln(file, "No fragmentation found.")
	} else {
		for _, data := range fragmentationData {
			fmt.Fprintf(file, "%s\t%d\t\t%d\t\t\t%d\n", data.identifier, data.srcPort, data.dstPort, data.fragmentCount)
		}
	}
	fmt.Println("Fragmentation statistics calculation completed.")
}


// calculateDNSResolutionDelays calculates the DNS resolution delays for each query and writes the results to a file.
// It processes DNS query and response data to calculate the delay between them and stores the results.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func calculateDNSResolutionDelays(timestamp string) {
	fmt.Println("Calculating DNS resolution delays...")
	filePath := fmt.Sprintf("dns_resolution_delays_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	// Sort DNS delays by delay in descending order
	sort.Slice(dnsDelays, func(i, j int) bool {
		return dnsDelays[i].delay > dnsDelays[j].delay
	})

	// Write DNS resolution delay data to file
	fmt.Fprintln(file, "Query\tSource_Destination\tQuery Time\tResponse Time\tDelay")
	for _, data := range dnsDelays {
		identifier := generateIdentifier(data.srcIP, data.dstIP)
		fmt.Fprintf(file, "%s\t%s\t%s\t%s\t%s\n", data.query, identifier, data.queryTime, data.respTime, data.delay)
	}
	fmt.Println("DNS resolution delays calculation completed.")
}


// calculateErrorMessageCounts calculates the count of different error messages for each connection
// and writes the results to a file. It filters out non-error messages such as Echo Request and Echo Reply.
//
// Parameters:
// - timestamp: A string representing the current timestamp to uniquely name the output file.
func calculateErrorMessageCounts(timestamp string) {
	fmt.Println("Calculating error message counts...")
	filePath := fmt.Sprintf("error_message_counts_%s.txt", timestamp)

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer file.Close()

	type errorMessageInfo struct {
		identifier string
		errorType  string
		count      int
	}

	var errorMessageList []errorMessageInfo

	// Collect error messages into a list
	for identifier, errMap := range errorMessages {
		for errType, count := range errMap {
			// Only include actual error messages, filter out Echo Request and Echo Reply
			if errType != "Echo Request" && errType != "Echo Reply" {
				errorMessageList = append(errorMessageList, errorMessageInfo{
					identifier: identifier,
					errorType:  errType,
					count:      count,
				})
			}
		}
	}

	// Sort error messages by count in descending order
	sort.Slice(errorMessageList, func(i, j int) bool {
		return errorMessageList[i].count > errorMessageList[j].count
	})

	// Write error message counts to file
	fmt.Fprintln(file, "Source_Destination\tError Type\tCount")
	for _, data := range errorMessageList {
		fmt.Fprintf(file, "%s\t%s\t\t%d\n", data.identifier, data.errorType, data.count)
	}
	fmt.Println("Error message counts calculation completed.")
}


// analyzeFile reads a file and analyzes the suspect scores for each connection based on the content.
// It increments the suspect score for each identifier found in the file.
//
// Parameters:
// - filePath: The path to the file to be analyzed.
func analyzeFile(filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open file %s: %v", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) > 0 && strings.Contains(parts[0], "_") {
			identifier := parts[0]
			if _, exists := suspectScores[identifier]; !exists {
				suspectScores[identifier] = 0
			}
			suspectScores[identifier]++
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file %s: %v", filePath, err)
	}
}


// calculateSuspectScores processes multiple files to calculate suspect scores for various network metrics.
// It reads each file, extracts relevant metrics, and updates suspect scores and their contributions.
//
// Parameters:
// - filePaths: A slice of strings containing the paths to the files to be processed.
func calculateSuspectScores(filePaths []string) {
	log.Println("Starting to calculate suspect scores...")

	for _, filePath := range filePaths {
		log.Printf("Processing file: %s", filePath)
		file, err := os.Open(filePath)
		if err != nil {
			log.Fatalf("Failed to open file %s: %v", filePath, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Fields(line)
			if len(parts) > 0 && strings.Contains(parts[0], "_") && !strings.Contains(parts[0], "Source_Destination") {
				identifier := parts[0]

				if _, exists := suspectScores[identifier]; !exists {
					suspectScores[identifier] = 0
				}
				if _, exists := metricContributions[identifier]; !exists {
					metricContributions[identifier] = make(map[string]int)
				}
				if _, exists := rawMetrics[identifier]; !exists {
					rawMetrics[identifier] = make(map[string]interface{})
				}

				log.Printf("Processing identifier %s in file %s", identifier, filePath)

				// Process jitter
				if strings.Contains(filePath, "jitter") {
					jitter, err := time.ParseDuration(parts[3])
					if err != nil {
						log.Printf("Error parsing jitter for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["jitter"] = jitter.Seconds()
					if jitter > 30*time.Millisecond {
						jitterAbove30ms := int(jitter.Milliseconds() - 30)
						suspectScores[identifier] += jitterAbove30ms
						metricContributions[identifier]["jitter"] += jitterAbove30ms
						log.Printf("Jitter processed for %s: %d", identifier, jitterAbove30ms)
					}
				}

				// Process duplicate ACKs
				if strings.Contains(filePath, "duplicate_acks") {
					dupAcks, err := strconv.Atoi(parts[2])
					if err != nil {
						log.Printf("Error parsing duplicate ACKs for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["duplicate_acks"] = dupAcks
					if dupAcks > 100 {
						suspectScores[identifier] += dupAcks - 100
						metricContributions[identifier]["duplicate_acks"] += dupAcks - 100
						log.Printf("Duplicate ACKs processed for %s: %d", identifier, dupAcks-100)
					}
				}

				// Process error messages
				if strings.Contains(filePath, "error_message_counts") {
					errorCount, err := strconv.Atoi(parts[2])
					if err != nil {
						log.Printf("Error parsing error messages for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["error_message_counts"] = errorCount
					suspectScores[identifier] += errorCount
					metricContributions[identifier]["error_message_counts"] += errorCount
					log.Printf("Error messages processed for %s: %d", identifier, errorCount)
				}

				// Process handshake failures and connection breaks
				if strings.Contains(filePath, "handshake_failures_and_connection_breaks") {
					handshakeFailures, err := strconv.Atoi(parts[1])
					if err != nil {
						log.Printf("Error parsing handshake failures for %s: %v", identifier, err)
						continue
					}
					connectionBreaks, err := strconv.Atoi(parts[2])
					if err != nil {
						log.Printf("Error parsing connection breaks for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["handshake_failures"] = handshakeFailures
					rawMetrics[identifier]["connection_breaks"] = connectionBreaks
					suspectScores[identifier] += handshakeFailures + connectionBreaks
					metricContributions[identifier]["handshake_failures_and_connection_breaks"] += handshakeFailures + connectionBreaks
					log.Printf("Handshake failures and connection breaks processed for %s: %d", identifier, handshakeFailures+connectionBreaks)
				}

				// Process latency percentages
				if strings.Contains(filePath, "latency_percentages") {
					percentageStr := strings.TrimSuffix(parts[2], "%")
					percentage, err := strconv.ParseFloat(percentageStr, 64)
					if err != nil {
						log.Printf("Error parsing latency percentages for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["latency_percentages"] = percentage
					if percentage > 100 {
						suspectScores[identifier] += int(percentage - 100)
						metricContributions[identifier]["latency_percentages"] += int(percentage - 100)
						log.Printf("Latency percentages processed for %s: %d", identifier, int(percentage-100))
					}
				}

				// Process retransmissions
				if strings.Contains(filePath, "retransmissions") {
					retransmissions, err := strconv.Atoi(parts[3])
					if err != nil {
						log.Printf("Error parsing retransmissions for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["retransmissions"] = retransmissions
					suspectScores[identifier] += retransmissions
					metricContributions[identifier]["retransmissions"] += retransmissions
					log.Printf("Retransmissions processed for %s: %d", identifier, retransmissions)
				}

				// Process RTT data
				if strings.Contains(filePath, "rtt_data") {
					rtt, err := time.ParseDuration(parts[1])
					if err != nil {
						log.Printf("Error parsing RTT for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["rtt"] = rtt.Seconds()
					if rtt > 30*time.Millisecond {
						rttAbove30ms := int(rtt.Milliseconds() - 30)
						suspectScores[identifier] += rttAbove30ms
						metricContributions[identifier]["rtt_data"] += rttAbove30ms
						log.Printf("RTT processed for %s: %d", identifier, rttAbove30ms)
					}
				}

				// Process fragmentation
				if strings.Contains(filePath, "fragmentation") {
					fragmentCount, err := strconv.Atoi(parts[3])
					if err != nil {
						log.Printf("Error parsing fragmentation for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["fragmentation"] = fragmentCount
					suspectScores[identifier] += fragmentCount
					metricContributions[identifier]["fragmentation"] += fragmentCount
					log.Printf("Fragmentation processed for %s: %d", identifier, fragmentCount)
				}

				// Process DNS resolution delays
				if strings.Contains(filePath, "dns_resolution_delays") {
					delay, err := time.ParseDuration(parts[4])
					if err != nil {
						log.Printf("Error parsing DNS resolution delay for %s: %v", identifier, err)
						continue
					}
					rawMetrics[identifier]["dns_resolution_delays"] = delay.Seconds()
					if delay > 100*time.Millisecond {
						latencyAbove100ms := int(delay.Milliseconds() - 100)
						suspectScores[identifier] += latencyAbove100ms
						metricContributions[identifier]["dns_resolution_delays"] += latencyAbove100ms
						log.Printf("DNS resolution delays processed for %s: %d", identifier, latencyAbove100ms)
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading file %s: %v", filePath, err)
		}
	}
	log.Println("Finished calculating suspect scores.")
}


func writeSummary(filePath string, timestamp string) {
	log.Println("Starting to write summary...")

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("Failed to create summary file: %v", err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			log.Fatalf("Failed to close summary file: %v", err)
		}
	}()

	type suspectInfo struct {
		identifier string
		score      int
	}

	var suspects []suspectInfo
	for identifier, score := range suspectScores {
		if isValidIPPair(identifier) {
			suspects = append(suspects, suspectInfo{identifier, score})
		}
	}

	sort.Slice(suspects, func(i, j int) bool {
		return suspects[i].score > suspects[j].score
	})

	// Calculate the top 25% suspects
	top25Count := (len(suspects) + 3) / 4 // Using (len(suspects) + 3) / 4 to round up

	log.Println("Writing top suspects with percentages to the file...")

	// Write top suspects with percentages to the file
	fmt.Fprintln(file, "Top Suspects with Total Suspect Score and Suspect Score Composition Percentages")
	fmt.Fprintf(file, "%-30s%-15s%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s\n",
		"Source_Destination", "Suspect Score", "%dup_ack", "%err_msg", "%hsf_cnb", "%jtr", "%hgh_lat", "$rtm", "%wdw_dlt", "%rtt", "%frg", "%dns_rsd")
	for i := 0; i < top25Count; i++ {
		suspect := suspects[i]
		score := suspect.score
		contributions := metricContributions[suspect.identifier]
		totalScore := float64(score)

		log.Printf("Writing suspect: %s with score: %d", suspect.identifier, score)

		fmt.Fprintf(file, "%-30s%-15d%-10.2f%-10.2f%-10.2f%-10.2f%-10.2f%-10.2f%-10.2f%-10.2f%-10.2f%-10.2f\n",
			suspect.identifier, score,
			normalize(contributions["duplicate_acks"], totalScore),
			normalize(contributions["error_message_counts"], totalScore),
			normalize(contributions["handshake_failures_and_connection_breaks"], totalScore),
			normalize(contributions["jitter"], totalScore),
			normalize(contributions["latency_percentages"], totalScore),
			normalize(contributions["retransmissions"], totalScore),
			normalize(contributions["window_size"], totalScore),
			normalize(contributions["rtt_data"], totalScore),
			normalize(contributions["fragmentation"], totalScore),
			normalize(contributions["dns_resolution_delays"], totalScore))
	}

	log.Println("Writing top suspects with raw metrics to the file...")

	// Write top suspects with raw metrics to the file
	fmt.Fprintln(file, "\nTop Suspects with Total Suspect Score and Raw Metrics")
	fmt.Fprintf(file, "%-30s%-15s%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s\n",
		"Source_Destination", "Suspect Score", "#dup_ack", "#err_msg", "#hsf_cnb", "#jtr", "#hgh_lat", "#rtm", "#wdw_dlt", "#rtt", "#frg", "#dns_rsd")
	for i := 0; i < top25Count; i++ {
		suspect := suspects[i]
		raw := rawMetrics[suspect.identifier]

		log.Printf("Writing raw metrics for suspect: %s with score: %d", suspect.identifier, suspect.score)

		fmt.Fprintf(file, "%-30s%-15d%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s%-10s\n",
			suspect.identifier, suspect.score,
			formatMetric(raw, "duplicate_acks"),
			formatMetric(raw, "error_message_counts"),
			formatMetric(raw, "handshake_failures_and_connection_breaks"),
			formatMetric(raw, "jitter"),
			formatMetric(raw, "latency_percentages"),
			formatMetric(raw, "retransmissions"),
			formatMetric(raw, "window_size"),
			formatMetric(raw, "rtt"),
			formatMetric(raw, "fragmentation"),
			formatMetric(raw, "dns_resolution_delays"))
	}

	log.Println("Writing relevant entries for each top suspect...")

	// Include relevant entries from each file for each top suspect
	filesToAnalyze := []string{
		fmt.Sprintf("retransmissions_%s.txt", timestamp),
		fmt.Sprintf("latency_percentages_%s.txt", timestamp),
		fmt.Sprintf("fragmentation_%s.txt", timestamp),
		fmt.Sprintf("dns_resolution_delays_%s.txt", timestamp),
		fmt.Sprintf("duplicate_acks_%s.txt", timestamp),
		fmt.Sprintf("handshake_failures_and_connection_breaks_%s.txt", timestamp),
		fmt.Sprintf("jitter_%s.txt", timestamp),
		fmt.Sprintf("rtt_data_%s.txt", timestamp),
		fmt.Sprintf("window_size_%s.txt", timestamp),
		fmt.Sprintf("error_message_counts_%s.txt", timestamp),
	}

	// Write relevant entries for each top suspect
	for i := 0; i < top25Count; i++ {
		suspect := suspects[i]
		identifier := suspect.identifier
		fmt.Fprintf(file, "\nEntries for %s:\n", identifier)
		for _, filePath := range filesToAnalyze {
			log.Printf("Processing file %s for identifier %s", filePath, identifier)
			writeRelevantEntries(file, identifier, filePath, timestamp)
		}
	}
	log.Println("Analysis summary written.")
}

// Helper function to format metrics
func formatMetric(metrics map[string]interface{}, key string) string {
	if value, exists := metrics[key]; exists {
		return fmt.Sprintf("%v", value)
	}
	return "n/a"
}

// Helper function to normalize contributions
func normalize(contribution int, totalScore float64) float64 {
	if totalScore == 0 {
		return 0.0
	}
	return (float64(contribution) / totalScore) * 100
}

func writeRelevantEntries(file *os.File, identifier string, filePath string, timestamp string) {
	fileToRead, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Failed to open file %s: %v", filePath, err)
	}
	defer fileToRead.Close()

	scanner := bufio.NewScanner(fileToRead)
	categoryWritten := false

	headers := map[string]string{
		"retransmissions":                          "Source_Destination\tSource Port\tDestination Port\tRetransmissions",
		"latency_percentages":                      "Source_Destination\tLatency Category\tPercentage",
		"fragmentation":                            "Source_Destination\tSource Port\tDestination Port\tFragment Count",
		"dns_resolution_delays":                    "Query\tSource_Destination\tQuery Time\tResponse Time\tDelay",
		"duplicate_acks":                           "Source_Destination\tDuplicate ACKs",
		"handshake_failures_and_connection_breaks": "Source_Destination\tHandshake Failures\tConnection Breaks",
		"jitter":               "Source_Destination\tSource Port\tDestination Port\tAverage Jitter",
		"rtt_data":             "Source_Destination\tRTT",
		"window_size":          "Source_Destination\tSource Port\tDestination Port\tMin Window Size\tMax Window Size\tAvg Window Size\tDelta",
		"error_message_counts": "Source_Destination\tError Type\tCount",
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, identifier) {
			if !categoryWritten {
				category := strings.TrimSuffix(filePath, fmt.Sprintf("_%s.txt", timestamp))
				header, exists := headers[category]
				if exists {
					fmt.Fprintf(file, "\nCategory: %s\n%s\n", filePath, header)
				} else {
					fmt.Fprintf(file, "\nCategory: %s\n", filePath)
				}
				categoryWritten = true
			}

			// Filter entries for latency percentages to include only those greater than 100ms
			if strings.Contains(filePath, "latency_percentages") {
				parts := strings.Fields(line)
				percentage, _ := strconv.Atoi(parts[2])
				if percentage > 100 {
					fmt.Fprintln(file, line)
				}
			} else {
				fmt.Fprintln(file, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading file %s: %v", filePath, err)
	}
}

func analyzeResults(timestamp string) {
	fmt.Println("Analyzing results...")

	// List of file paths to analyze
	filesToAnalyze := []string{
		fmt.Sprintf("retransmissions_%s.txt", timestamp),
		fmt.Sprintf("latency_percentages_%s.txt", timestamp),
		fmt.Sprintf("fragmentation_%s.txt", timestamp),
		fmt.Sprintf("dns_resolution_delays_%s.txt", timestamp),
		fmt.Sprintf("duplicate_acks_%s.txt", timestamp),
		fmt.Sprintf("handshake_failures_and_connection_breaks_%s.txt", timestamp),
		fmt.Sprintf("jitter_%s.txt", timestamp),
		fmt.Sprintf("rtt_data_%s.txt", timestamp),
		fmt.Sprintf("window_size_%s.txt", timestamp),
		fmt.Sprintf("error_message_counts_%s.txt", timestamp),
	}

	// Calculate suspect scores
	calculateSuspectScores(filesToAnalyze)

	// Write the summary
	outputFilePath := fmt.Sprintf("analysis_summary_%s.txt", timestamp)
	writeSummary(outputFilePath, timestamp)

	// Add the summary file to the list of files to zip
	filesToAnalyze = append(filesToAnalyze, outputFilePath)

	// Create a zip file containing all the files
	zipFileName := fmt.Sprintf("analysis_results_%s.zip", timestamp)
	err := createZipFile(zipFileName, filesToAnalyze)
	if err != nil {
		log.Fatalf("Failed to create zip file: %v", err)
	}

	fmt.Println("Analysis completed and results are zipped.")
}

func createZipFile(zipFileName string, files []string) error {
	// Create a new zip file
	zipFile, err := os.Create(zipFileName)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	// Create a new zip writer
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add files to the zip
	for _, file := range files {
		err := addFileToZip(zipWriter, file)
		if err != nil {
			return err
		}
	}

	return nil
}

func addFileToZip(zipWriter *zip.Writer, filePath string) error {
	// Open the file to be added to the zip
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get the file information
	info, err := file.Stat()
	if err != nil {
		return err
	}

	// Create a zip header based on the file info
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.Base(filePath)
	header.Method = zip.Deflate

	// Create a writer for the file in the zip
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	// Copy the file data to the zip writer
	_, err = io.Copy(writer, file)
	if err != nil {
		return err
	}

	// Close the file before deleting it
	file.Close()

	// Delete the file after it has been added to the zip
	err = os.Remove(filePath)
	if err != nil {
		return err
	}

	return nil
}
