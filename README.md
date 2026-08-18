# CodeAlpha Basic Network Sniffer

## Project Overview

This project is a Python-based Basic Network Sniffer developed as part of the CodeAlpha Cyber Security Internship.

The application captures network packets and analyzes important packet information such as source IP address, destination IP address, protocol, source port, destination port, packet size, timestamp, and a limited payload preview.

## Objective

The objective of this project is to understand how network traffic flows between devices and how different network protocols can be identified and analyzed.

## Features

- Captures network packets using Scapy
- Displays source IP address
- Displays destination IP address
- Identifies network protocols
- Displays source and destination ports
- Displays packet size
- Displays packet timestamp
- Provides a limited payload preview
- Captures and analyzes 20 IP packets per execution
- Automatically stops after the configured number of packets

## Technologies Used

- Python
- Scapy
- Npcap
- Windows PowerShell

## Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
│
├── network_sniffer.py
├── requirements.txt
├── README.md
└── screenshots/
