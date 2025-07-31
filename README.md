# 🛡️ URLDfender — Hunt Down Malicious URLs Before They Hunt You

> "One click can compromise an entire system. Make that click go through URLDfender."  
> — A tool by **mr.duice** for those who refuse to be victims.

---

## ⚔️ What is URLDfender?

**URLDfender** is a standalone, GUI-based Python application crafted for one purpose: **detect, analyze, and neutralize** suspicious or malicious URLs before they become a threat. It's a powerful tool for:

- 👨‍🎓 Cybersecurity students learning how attacks begin  
- 🧑‍💻 Bug hunters scanning payload links  
- 🧠 Educators training the next generation of cyber warriors  
- 🧑‍🚀 Everyday users who don’t want to be scammed  

Whether you’re analyzing suspicious links, building your malware lab arsenal, or preparing for the next red-team scenario — URLDfender has your back.

---

## 🌐 Key Functionalities

| Feature              | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| ✅ URL Validator      | Ensures the format, structure, and schema of a URL is legit                 |
| 🌐 WHOIS Lookup       | Fetches domain registration, age, expiry, and ownership                     |
| 🧠 Phishing Intelligence | Flags shortened links, hex-obfuscated domains, suspicious keywords         |
| 🧬 Entropy & Heuristics | Detects encoded patterns often used in phishing kits                      |
| 🔁 Redirect Detection | Follows redirects and warns of dangerous chains                             |
| 🛰 DNS Intelligence   | Gets A records and maps IPs to geolocation or suspicious blocks              |
| 🖥 Built-in GUI       | Crafted with tkinter, so no CLI hassle — just launch and go                 |
| 💾 Offline Friendly   | Basic heuristics work even without internet connection                      |

---

## 🚀 Demo Preview

> 📷 GUI Screenshot coming soon! 

### Example:

`Input a URL ➤ Get a verdict: Safe ✅ | Suspicious ⚠ | Dangerous ❌`

---

## 🏗️ How URLDfender Works

1. **User inputs a URL via GUI**
2. Tool performs:
   - ✅ Syntax & structure validation  
   - 🌐 WHOIS lookup for domain intel  
   - 🛰 DNS query to resolve host  
   - 🔁 Redirection path tracing  
   - 🧠 Heuristic checks (entropy, suspicious words, shortening, etc.)
3. **Result is displayed** in a user-friendly window with detailed findings.

No guesswork. No delays. Just solid URL forensics — instantly.

---

## 💻 Tech Stack

- 🐍 Python 3.x  
- 🪟 Tkinter for GUI  
- 🌐 Requests for networking  
- 🔬 BeautifulSoup & LXML for parsing  
- 🔎 WHOIS & DNSPython for domain info  
- 🧠 Regex & entropy algorithms for logic  

---

## 📦 Installation

### 🔧 Requirements

Install the required libraries:
```bash
requests  
validators  
beautifulsoup4  
lxml  
tk  
whois  
dnspython  
urllib3  
idna  
tldextract
```

---

## 🚀 Run the Tool
 ```bash
python urldfender.py
```
## 🔍 Use Cases

- 🧑‍🎓 **Training** – Perfect for cyber labs & student projects  
- 🧠 **Learning** – Understand how phishing links are constructed  
- 🕵 **Investigating** – Decode shady links from messages/emails  
- ⚔ **Defending** – Scan links before someone else clicks them  
- 👨‍💻 **Developing** – Plug this into a larger threat detection pipeline  

---

## 🧠 Designed With Hacker Logic

URLDfender doesn't just validate a URL — it **thinks like an attacker**:

- 🔗 Is someone hiding this behind a URL shortener?  
- 🔐 Is this URL full of base64 or hex encoding?  
- 🕒 Is the domain too new to be trusted?  
- 🧩 Is it trying to look like a legitimate site (e.g., `g00gle.com`)?  
- 🖥 Is it hosted on an IP address instead of a domain?  

> If the answer is yes — **URLDfender will tell you.**

---

## 🧑‍🔬 Advanced Roadmap (Coming Soon)

- 📊 Save scan logs in JSON/CSV  
- 🧪 VirusTotal & AbuseIPDB integration  
- 🌐 Browser automation for deeper analysis  
- 📡 Passive DNS info  
- ⚙ Command-line flags for headless scanning  
- ☁ Web version (Flask/Django) for online use  

---

## 👨‍💻 Developed By

**mr.duice**  
Cybersecurity Enthusiast | Penetration Tester in Training | Bug Hunter  

**Connect with me:**

- 🔗 [LinkedIn](www.linkedin.com/in/devashish-umale-3a793823a)  
- 💥 [TryHackMe](https://tryhackme.com/p/mr.duice)  
- 🧠 [GitHub Projects](https://github.com/mrDuice/Apocalyptic-Encryption-Assault-AEA-.git)  

---

## 🛡 License

Licensed under the **MIT License** — use it, share it, enhance it.  
Just **don’t use it for malicious purposes**. Stay ethical, always.

---

## 🌟 Star & Support

If this tool helped you:

- ✅ Star the repository  
- ✅ Fork it and add your own modules  
- ✅ Share with cybersecurity peers  
- ✅ Feature in your YouTube/LinkedIn project demo  

> Your support fuels the fire of open-source hacking tools. 🔥

---

## 📌 Final Words

**URLDfender** is more than just a Python script —  
It’s your **mini digital firewall** for URL threats.

🚫 Don’t blindly trust links.  
🧠 Train hard.  
💻 Code harder.  
🛡 Defend always.
                                                                                                                         
