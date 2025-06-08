# DNSNetGuard

DNSNetGuard is an advanced network interceptor that monitors and optionally blocks DNS and TLS SNI traffic to domains associated with spyware, malware, and adware.

## Features

* **DNS & TLS SNI Inspection:** Analyzes DNS queries and TLS Client Hello packets to identify target domains.
* **Threat Categorization:** Classifies domains into Whitelisted, Malware C2, Telemetry/Spyware, and Adware/Tracker categories.
* **Monitor or Block Mode:** Run in passive monitoring mode to detect threats, or enable active blocking.
* **Configurable Domain Patterns:** Easily update domain blacklists and whitelists.
* **Real-time Logging & Statistics:** Provides immediate feedback and summarizes session activity.

## Usage

**Requires Administrator privileges.**

* **Monitor Mode (Default):**
    ```bash
    python main.py
    ```
* **Block Mode:**
    ```bash
    python main.py -b
    ```
* **Verbose Output (shows all traffic):**
    ```bash
    python main.py -v
    ```
* **Block Mode with Verbose Output:**
    ```bash
    python main.py -b -v
    ```
