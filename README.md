
# 🛡️ Net-Sentinel

## 📌 Overview

A full-stack network security and monitoring system that discovers
devices across a network, scans open ports and services, and provides a
centralized dashboard and API for real-time visibility across multiple
virtual machines.

The project simulates a real-world network reconnaissance and asset
discovery platform used in cybersecurity environments.

------------------------------------------------------------------------

## 🚀 Features

-   Network host discovery (multi-VM support)
-   Port scanning using Nmap
-   Service and version detection
-   OS detection (optional)
-   Web dashboard for visualization (Flask)
-   REST API for scan results
-   JSON / database export of scan data
-   Real-time monitoring (future improvement)

------------------------------------------------------------------------

## 🏗️ Architecture

Client Dashboard -\> Flask API -\> Scan Engine (Python) -\> Nmap -\>
Virtual Network

------------------------------------------------------------------------

## 🛠️ Technologies Used

-   Python
-   Nmap
-   Flask
-   Linux (Kali / Ubuntu)
-   SQLite / JSON
-   VirtualBox / VMware

------------------------------------------------------------------------

## ⚙️ Installation

git clone https://github.com/yourusername/net-sentinel.git cd
net-sentinel pip install -r requirements.txt

------------------------------------------------------------------------

## ▶️ Usage

python scanner.py python api.py

Dashboard: http://127.0.0.1:5000

------------------------------------------------------------------------

## ⚠️ Disclaimer

For educational and authorized testing only.
