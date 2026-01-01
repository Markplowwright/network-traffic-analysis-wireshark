# Network-traffic-analysis-wireshark
Network Traffic Analysis & PCAP Automation
Overview

This repository documents a hands-on network traffic analysis and automation project focused on diagnosing TCP connection failures, authentication issues, and abnormal network behavior using Wireshark, tshark, and Python.

The project combines manual packet-level inspection with automated PCAP triage to identify SSH brute-force indicators, TCP retransmissions, reset conditions, and DNS resolution failures. Baseline traffic is captured and compared against abnormal scenarios to demonstrate structured troubleshooting, security awareness, and operational scalability.

This project reflects real-world workflows used in IT operations, network engineering, and security environments where analysts must quickly identify signal, validate findings, and escalate appropriately.

Objectives

Perform packet-level troubleshooting using Wireshark

Automate initial PCAP triage using Python

Analyze TCP connection lifecycle and failure modes

Detect SSH brute-force behavior through traffic patterns

Compare baseline traffic against abnormal conditions

Document a repeatable investigation workflow

Tools & Technologies

Wireshark – Manual packet inspection and flow analysis

tshark – Command-line packet analysis

Python – Automated PCAP summarization and anomaly detection

TCP/IP – Protocol-level analysis

SSH, DNS, HTTP, FTP

Linux command-line tools

Traffic Scenarios Analyzed
1. Baseline Network Traffic

Captured normal TCP connections, successful SSH authentication, and standard DNS resolution.

Purpose:
Establish expected behavior for comparison against abnormal traffic.

2. SSH Brute-Force Behavior

Analyzed repeated SSH authentication attempts to identify brute-force indicators.

Key Observations:

Repeated TCP handshakes to port 22

Rapid authentication failures

Consistent source IP across attempts

Predictable retry timing patterns

3. TCP Retransmissions and Resets

Captured scenarios involving packet loss, blocked ports, and forced connection teardown.

Key Observations:

SYN retransmissions

Duplicate ACKs

TCP RST packets

Half-open and failed connections

4. DNS Resolution Failure

Analyzed failed DNS queries and downstream application impact.

Key Observations:

Unanswered DNS queries

Retransmissions due to timeouts

Application-level connection failures

Automated PCAP Analysis (Python)

To improve scalability and reduce manual triage time, a Python script was developed to summarize PCAP files and highlight suspicious patterns before deep inspection.

Script Capabilities

Counts TCP SYN packets and failed handshakes

Identifies TCP retransmissions and reset packets

Detects repeated SSH authentication attempts

Flags potential brute-force behavior based on thresholds

Example Output
PCAP Summary:
- Total TCP Connections: 312
- Failed Handshakes: 48
- TCP Resets: 21
- SSH Authentication Failures: 96
- Potential Brute-Force Detected: YES


This allows analysts to quickly determine whether a PCAP requires deeper manual analysis.

Command-Line Analysis (tshark)

tshark is used to complement Wireshark by enabling fast, repeatable filtering from the command line.

Example:

tshark -r ssh_bruteforce_attempt.pcap -Y "tcp.flags.reset==1"


This approach supports automation, scripting, and analysis of large capture files.
Details are documented in docs/cli-analysis.md.

Manual vs Automated Analysis
Task	Wireshark (Manual)	Python / tshark (Automated)
Identify retransmissions	Yes	Yes
Count failed handshakes	Manual	Automatic
Detect SSH brute force	Visual	Threshold-based
Analyze large PCAPs	Limited	Scalable
Initial triage	Slow	Fast
Investigation Methodology

Each scenario follows a consistent workflow:

Problem Definition

Capture Strategy

Baseline Comparison

Hypothesis Formation

Validation via Packet Evidence

Conclusion and Recommendation

This workflow is documented in docs/investigation-workflow.md.

Production Considerations

Automated triage reduces alert fatigue and investigation time

Manual inspection is used for validation and root cause analysis

Threshold-based detection must be tuned to avoid false positives

Packet captures may contain sensitive data and should be handled securely

Skills Demonstrated

Packet-level troubleshooting

TCP flow and handshake analysis

Security-aware traffic inspection

Automation and scripting

Operational and investigative thinking

Use Cases

IT Support & Technical Support Engineering

Network Operations Center (NOC)

Security Operations Center (SOC)

Incident response and escalation

Key Takeaways

This project demonstrates the ability to analyze network traffic at both a detailed and scalable level. By combining protocol-level knowledge, automation, and structured investigation, it reflects real-world operational workflows rather than isolated lab exercises.

Author

Mark
Network Troubleshooting | Security-Aware Analysis
GitHub: your-profile-link
