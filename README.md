# Mirai Source Code (FOR EDUCATIONAL & RESEARCH| `README.md`       | You're reading it                                     |


# Table of Contents

- [About Mirai](#about-mirai)
- [Repository Structure](#repository-structure)
- [Requirements](#-requirements)
- [How To Use (Lab Research Only)](#how-to-use-for-lab-research-only)
- [Learning Use Cases](#learning-use-cases)
- [Do NOT Use For](#Implications-Not-To-Use-For)
- [References](#references)
- [Credits](#credits)
- [Acknowledgments](#acknowledgments)


⚠️ **CRITICAL DISCLAIMER**  
This repository contains the leaked source code of the **Mirai botnet**, originally created to infect IoT devices and launch large-scale DDoS attacks. This code is provided **strictly for cybersecurity research, reverse engineering, malware analysis, and detection development purposes only**.

**⚠️ WARNING**      
Do Not Use This Code To Attack or Scan Any Real Devices or Networks. Unauthorized Use Is Illegal and Violates GitHub Policy.

**🛡️ SECURITY NOTICE**    
The [zip file](https://www.virustotal.com/en/file/f10667215040e87dae62dd48a5405b3b1b0fe7dbbfbf790d5300f3cd54893333/analysis/1477822491/) for this repo is being identified by some AV programs as malware. Please take caution.

---

# About Mirai

Mirai is a malware botnet that infects Internet of Things (IoT) devices using default or weak login credentials. Once infected, these devices are controlled by a command-and-control (CnC) server and can be used to launch DDoS attacks.

This repo is a fork of the original leaked source code and includes components such as:
- The bot (runs on IoT devices)
- The CnC server
- The loader (infects devices)
- Scanning and deployment scripts

---

# Repository Structure

| Directory/File       | Description                                           |
|-------------------|-------------------------------------------------------|
| `mirai/`          | Core malware source code (bot + CnC server)          |
| `loader/`         | Infects vulnerable devices using telnet brute-force  |
| `dlr/`            | Possibly supports payload delivery (optional)        |
| `scripts/`        | Scripts for building and managing the malware        |
| `ForumPost.txt`   | Original forum post by author explaining Mirai       |
| `LICENSE.md`      | License as included in original leak (not official)  |
| `README.md`       | You’re reading it                                     |

---

# Requirements

Before building and running this code, ensure you have the following installed on a **Linux host**:

- `gcc` - GNU Compiler Collection
- `golang` - Go programming language
- `electric-fence` - Memory debugging library
- `mysql-server` - MySQL database server
- `mysql-client` - MySQL database client
- `build-essential` - Essential build tools
- `crossbuild-essential-armel` - Cross-compilation tools for ARM **Additional Resources:**
- For detailed setup instructions and background information, refer to the original leak post in `ForumPost.txt` or view the formatted version at [ForumPost.md](ForumPost.md).

---

# How to Use (FOR LAB RESEARCH ONLY)

> You must use **isolated VMs** or an offline network. Never run this on a real device or public network.

## 1. Prerequisites

Install on a **Linux host**:

```bash
sudo apt update
sudo apt install gcc make build-essential git crossbuild-essential-armel -y
```

## 2. Clone the Repository

```bash
git clone https://github.com/jgamblin/Mirai-Source-Code.git
cd Mirai-Source-Code
```

## 3. Build the Bot and CnC

```bash
./build.sh
```

**This will:**

* Cross-compile the bot for different IoT architectures (MIPS, ARM, etc.)

* Compile the CnC server for your local machine

You can customize the build script and source code paths if needed.

## 4. Setup a Test Lab (Recommended)

Create a virtual lab with:

* 1 Ubuntu VM for CnC and loader

* 1 or more OpenWRT/Linux VMs simulating IoT devices

Use Host-Only or Internal Networking mode to keep the lab isolated.

## 5. Running Components

* Start the CnC server (mirai/cnc/cnc)

* Run the loader to infect virtual IoT VMs

* Observe communication logs, infection, and payload delivery

# Learning Use Cases

You can use this source code to:

* Understand how botnets spread through weak credentials

* Reverse engineer malware behavior

* Write intrusion detection rules (YARA, Snort, Suricata)

* Develop antivirus and botnet defenses

* Study CnC-to-bot protocol and build simulators

# Implications Not To Use For

*  Scanning or infecting real IoT devices

*  DDoS attacks

*  Deploying the bot to the public internet

> Any such use is illegal and against GitHub policy. 

# References

* [Original Leak on Hackforums (2016)](https://hackforums.net/showthread.php?tid=5420472)
* [DDoS Analysis of Mirai by MalwareMustDie](https://blog.malwaremustdie.org/2016/10/mmd-0056-2016-new-mirai-elf-botnet.html)
* [US-CERT Alert TA16-288A](https://www.cisa.gov/news-events/alerts/2016/10/14/alert-ta16-288a)

# Credits

**Original Author:** [Anna-senpai](https://hackforums.net/showthread.php?tid=5420472) - Original Mirai botnet source code leak (2016)  
*Note: The original forum appears to be inactive as of now.*

# Acknowledgments

Special Thanks To [Jerry Gamblin](https://github.com/jgamblin) ,[Sam Gleske](https://github.com/samrocketman), [谢致邦 XIE Zhibang](https://github.com/Red54) , [Peter K. Shultz ](https://github.com/pkshultz), [BenjaminHCCarr](https://github.com/BenjaminHCCarr) , [Pushpenderrathore](https://github.com/Pushpenderrathore) For The Improved Project Structure and Comprehensive Documentation That Makes This Educational Resource More Accessible For Cybersecurity Research.

