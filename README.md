# 🔐 Built the Lock. Picked the Lock. Then Called the Cops on Myself.

> A two-episode hands-on security lab — building a vulnerable OAuth2 authentication server, simulating a credential stuffing attack, and detecting it in real time using Splunk.

---

## 📋 Incident Summary

| Field | Details |
|-------|---------|
| **Target** | Custom Node.js OAuth2 authentication server |
| **Attack Type** | Credential stuffing / Brute-force login |
| **Tool Used** | Burp Suite Intruder |
| **Detection Platform** | Splunk Enterprise |
| **Total Attack Events** | 137 LOGIN_FAILED, 4 LOGIN_SUCCESS |
| **Attacker IP** | `::ffff:127.0.0.1` (simulated) |
| **Targeted Account** | `admin` |
| **Cracked Password** | `admin123` (payload position 27/30) |

---

## 🗂 Project Structure

```
authentication-mock-up/
├── server.js          # Node.js OAuth2 server with security logger
├── logs/
│   └── security.log   # Structured JSON security events (Splunk input)
├── package.json
└── README.md
```

---

## 🔴 Episode 1 — Building the Lock

### What was built
A full OAuth2 authorization server using:
- **Node.js + Express** — REST API with login and token endpoints
- **Passport.js** — LocalStrategy and BearerStrategy authentication
- **oauth2orize** — Authorization code grant flow
- **bcrypt** — Password hashing with salt (work factor: 10)

### The Salt Problem
Without salt, two users with the same password produce identical hashes — a massive win for attackers. bcrypt solves this by adding a unique random salt before hashing.

```js
// Generating the hash
const hash = bcrypt.hashSync('admin123', 10);
// Output: $2a$10$bbc.ZA1Pca.Qxv.xmQSXSOIxHFA7STjc3KcNRwvqoTr1OZ2RZkGD.
//                  ^^^ work factor — hashing runs 2^10 = 1024 times
```

The `$2a$10$` prefix tells you exactly how it was hashed — algorithm, version, and cost factor.

---

## 🔴 Episode 2 — Picking the Lock (Attack Simulation)

### Setup
- Kali Linux VM (VirtualBox)
- Burp Suite Community Edition v2025.7.4
- Node.js server running on `localhost:3000`

### Attack Flow
1. Captured a `POST /login` request in Burp Proxy
2. Sent to **Intruder** → Sniper attack mode
3. Set payload position on the `password` field
4. Loaded a 30-password wordlist:
   ```
   password, 123456, password123, admin, letmein,
   welcome, monkey, dragon, master, abc123,
   donald, pass123, test, guest, admin123, root, toor, changeme...
   ```
5. Fired 30 requests — 29 returned `401`, 1 returned `200`
6. **Payload 27 — `admin123` — cracked**

![Burp Suite Intruder setup — payload position on password field](images/burpsuite-intruder-setup.png)

![Burp Suite Intruder results — payload 27 returns status 200](images/burpsuite-intruder-results.png)

### Security Log Output (sample)
```json
{"timestamp":"2026-03-15T02:40:11.319Z","event_type":"LOGIN_SUCCESS","endpoint":"/login","src_ip":"::ffff:127.0.0.1","username":"admin","user_id":"1","status":200}
{"timestamp":"2026-03-15T02:40:12.630Z","event_type":"LOGIN_FAILED","endpoint":"/login","src_ip":"::ffff:127.0.0.1","username":"admin","status":401,"reason":"Wrong password"}
```

![Security log output in terminal showing LOGIN_FAILED and LOGIN_SUCCESS events](images/security-log-output.png)

---

## 🔵 Episode 2 — Calling the Cops (Splunk Detection)

### Ingestion Setup
- Splunk Enterprise installed at `/opt/splunk`
- Data Input → Files & Directories → `logs/security.log`
- Source type: `_json`

### Detection Query — Brute Force Threshold
```spl
index=main sourcetype=_json
| spath event_type | spath src_ip
| search event_type="LOGIN_FAILED"
| bucket _time span=5m
| stats count by src_ip, _time
| where count >= 10
```

![Splunk brute-force detection query results](images/splunk-detection-query.png)

### Dashboard Panels

| Panel | Chart Type | SPL |
|-------|-----------|-----|
| Top Attacking IPs | Bar Chart | `stats count by src_ip \| sort -count` |
| Attack Timeline | Line Chart | `timechart span=5m count` |
| Targeted Usernames | Bar Chart | `stats count by username \| sort -count` |
| Failed vs Success | Pie Chart | `stats count by event_type` |
| Threat Correlation | Table | `stats count by src_ip, event_type` |

### Results
- **137 LOGIN_FAILED** from a single IP in one session
- Attack spike clearly visible on timeline
- `admin` was the only targeted username
- Same IP correlated across all event types

![Splunk dashboard — full view with all panels](images/splunk-dashboard-overview.png)

![Splunk attack timeline — spike of LOGIN_FAILED events](images/splunk-attack-timeline.png)

---

## 🛠 Tech Stack

| Layer | Tool |
|-------|------|
| Server | Node.js, Express |
| Auth | Passport.js, oauth2orize |
| Hashing | bcrypt |
| Attack Simulation | Burp Suite Community |
| Log Ingestion | Splunk Enterprise |
| Detection | SPL (Splunk Processing Language) |
| Lab Environment | Kali Linux, VirtualBox |

---

## 🚀 How to Run

### 1. Install dependencies
```bash
npm install
```

### 2. Start the server
```bash
node server.js
```

Server runs at `http://localhost:3000`

Demo credentials:
- Username: `admin`
- Password: `admin123`

### 3. Simulate attack (curl)
```bash
for i in {1..30}; do
  curl -s -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrongpass"}'
  sleep 0.5
done
```

### 4. Ingest into Splunk
- Settings → Data Inputs → Files & Directories
- Path: `/path/to/logs/security.log`
- Source type: `_json`

---

## 🖼 Screenshots

Screenshots are stored in the [`images/`](images/) directory. See [`images/README.md`](images/README.md) for the list of expected filenames and instructions on how to add your own.

---

## 📎 References
- [oauth2orize](https://github.com/jaredhanson/oauth2orize)
- [Passport.js](https://www.passportjs.org/)
- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder)

---

*Part of an ongoing hands-on cybersecurity series. Follow along on LinkedIn.*
