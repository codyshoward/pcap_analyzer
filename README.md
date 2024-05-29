PCAP Analyzer
Overview
This package provides a comprehensive tool for analyzing PCAP files, extracting various network metrics, and summarizing the results in a detailed analysis report. The tool also supports zipping the generated analysis files and deleting the original files after they are added to the zip.

How to use. 
1. Download the pcap_analyzer.exe
2. Run the pcap_analyzer.exe and select a pcap file.
3. Open the zipped folder created in the same directory as the pcap_analyzer.exe.
4. Review the Analysis_summary first, then review all other data as needed. 

Contact: Codyshoward@gmail.com

Features
Analyzes PCAP files for various network metrics including retransmissions, latency, handshake failures, connection breaks, RTT, jitter, throughput, duplicate ACKs, window sizes, fragmentation, DNS resolution delays, and error message counts.
Generates detailed analysis reports with suspect scores and raw metrics.
Zips the generated analysis files and deletes the original files after zipping.


Functions
Main Functions
main()

The entry point of the application. It sets up logging, opens a file selection dialog, processes the selected PCAP file, writes various analysis results to files, and generates a summary report.

PCAP Handling Functions
handlePcapTrns(filePath string)

Processes transactions in the PCAP file to extract retransmissions, handshake failures, connection breaks, and RTT.

handlePcapLat(filePath string)

Processes latency data in the PCAP file, including DNS queries and responses, ICMP errors, and TCP packet details.

Metric Calculation Functions
writeRetransmissionTable(timestamp string)
writeLatencyPercentages(timestamp string)
writeHandshakeFailuresAndConnectionBreaks(timestamp string)
writeRTTData(timestamp string)
calculateJitter(timestamp string)
calculateThroughput(timestamp string)
calculateDuplicateAcks(timestamp string)
calculateWindowSizeStatistics(timestamp string)
calculateFragmentationStatistics(timestamp string)
calculateDNSResolutionDelays(timestamp string)
calculateErrorMessageCounts(timestamp string)
Analysis Functions
analyzeFile(filePath string)

Analyzes a file and updates suspect scores based on the content.

calculateSuspectScores(filePaths []string)

Calculates suspect scores from the analysis files.

writeSummary(filePath string, timestamp string)

Writes the analysis summary, including suspect scores and raw metrics, to a file.

File Handling Functions
createZipFile(zipFileName string, files []string) error

Creates a zip file containing the specified files.

*addFileToZip(zipWriter zip.Writer, filePath string) error

Adds a file to the zip and deletes the original file after it is added.
