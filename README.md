# Multi-Layered-Hybrid-Defense-against-Architectural-Wormhole-Tunnels

### Project Overview
This project demonstrates a **Wormhole Attack** (Architectural Tunneling) and the implementation of a **Multi-Layered Intrusion Prevention System (IPS)**. While traditional defenses like DNSSEC verify data integrity, they often fail to detect path-based redirections. Our **Defender Tool** bridges this gap by using **Heuristic Infrastructure Analysis** to detect and block unauthorized network tunnels.

### The Attack: Wormhole Tunneling
The attack utilizes **Reverse SSH/Proxy Tunneling** to create a secret bridge between a public network and a private listener.

* **Entrance:** A public URL generated via `localtunnel` (`npx localtunnel`).
* **Mechanism:** Data is encapsulated and "warped" through a third-party relay (Cloudflare/Localtunnel AS), bypassing local firewall inspection.
* **Exit:** A Python-based backend listener that captures exfiltrated data in a private terminal environment.

### The Defense: Heuristic Intrusion Detection (HIDS)
The `defender_tool.py` operates as an **Active Mitigation System**, analyzing network traffic across three distinct layers:

#### **Layer 1: Deterministic IP Verification**
* **Technology:** A-Record Cross-Referencing.
* **Logic:** The tool compares the current **Resolved IP** against a **Trusted Baseline**. If the IP belongs to a known Proxy/Tunneling Autonomous System (ASN), a **Topology Anomaly** is triggered.

#### **Layer 2: DNSSEC Validation**
* **Technology:** Cryptographic Origin Authentication.
* **Logic:** Validates the **RRSIG** (Resource Record Signature) to ensure the domain record itself has not been tampered with. This proves that a "Verified" domain can still lead to a malicious "Path."

#### **Layer 3: Automated Mitigation (Blackhole Routing)**
* **Technology:** Incident Response Automation.
* **Logic:** Upon detection, the tool initiates a local **Blackhole Server** (127.0.0.1:9999) to trap malicious traffic, preventing the victim's data from reaching the wormhole exit.
  
---

### Detection Output Example
```text
============================================================
DNS SECURITY CHECK: www.example.com
============================================================
[LAYER 1] IP Address Verification
[*] Resolved IP: 172.66.147.243 (Tunnel Relay Detected)
[*] Trusted IP:  93.184.216.34 (Known-Good Baseline)
[!!!] CRITICAL: WORMHOLE ATTACK DETECTED!

[LAYER 2] DNSSEC Validation
[+] DNSSEC: VALIDATED - Origin Authenticated

[LAYER 3] Security Assessment
[+++] ACTIVE ATTACK DETECTED AND BLOCKED
[+++] Domain www.example.com is COMPLETELY BLOCKED
============================================================
```

---

### Installation & Usage

**1. Prerequisites**
* Python 3.10+
* Node.js (for `localtunnel`)

**2. Setup**
```bash
# Clone the repository
git clone https://github.com/yourusername/wormhole-defender.git

# Install dependencies
pip install -r requirements.txt
```

**3. Execution**
* **Run Attack Exit:** `python wormhole_exit.py`
* **Open Wormhole:** `npx localtunnel --port 8888`
* **Run Defender:** `python defender_tool.py`

---

### Key Technical Terms
* **ASN Filtering:** Detecting traffic coming from high-risk proxy/relay networks.
* **Topology Anomaly:** A deviation in the expected physical path of a network packet.
* **Blackhole Routing:** A mitigation technique that sends malicious traffic to a "dead-end" address.
* **OOB (Out-of-Band) Verification:** Checking data against a secondary, trusted source outside the primary network path.

---

### 📝 Conclusion
This project proves that **Identity (DNSSEC)** is not enough for modern security; **Path Integrity (IP Verification)** is required. By combining these layers, our Defender Tool provides a robust shield against stealthy tunneling attacks.
