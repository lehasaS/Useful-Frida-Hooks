# Useful-Frida-Hooks

This repository contains **Frida hooks** that have been useful to me for dynamic analysis, enumeration, and instrumentation of both Windows and Android applications. These scripts help monitor system calls, file and registry operations, memory allocation, network activity, and process behavior.

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Setup](#setup)

---

## Overview
Frida is a dynamic instrumentation toolkit for developers, reverse engineers, and security researchers. This repository contains prebuilt hooks to simplify:
- File and registry monitoring
- Memory allocation and protection tracking
- Network activity logging
- Process creation and DLL loading
- Android syscall monitoring
- Windows-specific crypto and heap instrumentation

These hooks allow you to inspect runtime behavior and detect suspicious or malicious activity such as:
- Heaven’s Gate technique on Windows
- Dynamic memory decryption
- Network connections and data exfiltration

---

## Features
- **Windows Hooks**
  - Kernel32 & Ntdll instrumentation
  - VirtualAlloc and VirtualProtect monitoring
  - File and registry operation hooks
  - Heap allocation logging (UTF-16 content extraction)
  - Crypto API hooks (`CryptUnprotectData`)
  - Process and DLL creation hooks

- **Android Hooks**
  - POSIX networking syscalls (`connect`, `send`, `recv`, `sendto`, `recvfrom`)
  - IP/port extraction for `sockaddr_in`
  - Data payload logging for network traffic

- **iOS Hooks**
  - Hooking **Objective-C** and **Swift** methods.
  - Monitoring **CoreFoundation**, **Security**, and network APIs.
  - Runtime memory and process monitoring.
  - Network traffic logging for apps using native iOS frameworks.


- **Automation**
  - Python scripts for auto-attaching to processes
  - CSV logging of instrumentation data
  - Child process gating and monitoring on Windows

---

## Requirements
- Python 3.10+  
- Frida (`pip install frida`)  
- Frida Tools (`pip install frida-tools`)  

All dependencies can be installed automatically using the `setup.py` script.

---

## Setup
1. Clone the repository:
```bash
git clone https://github.com/lehasaS/Useful-Frida-Hooks
cd Useful-Frida-Hooks
python3 setup.py
```
