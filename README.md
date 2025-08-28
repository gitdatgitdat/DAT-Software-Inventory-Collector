# DAT Software Inventory Collector

A lightweight Python utility to collect and export a list of installed software on a Windows machine.  
Built as a system administration learning project to practice automation, logging, and inventory management.

---

## Features

- Collects installed software via Windows registry  
- Outputs results to JSON or CSV  
- Easy to extend with additional collection methods (e.g., WMI, PowerShell)  
- Runs on standard Python without heavy dependencies  
- Useful for asset management, audits, or homelab tracking  

---

## Requirements

- Python 3.11+  
- Windows (registry queries for installed programs)  
- Run from a user with permissions to query the registry  

---

## Usage

Clone the repo and run:

    python collector.py

Options (to be extended):  
- Default output: `inventory.json`  
- CSV support planned  

Example output (`inventory.json`):

    [
      {
        "name": "Google Chrome",
        "version": "128.0.6613.120",
        "publisher": "Google LLC"
      },
      {
        "name": "Visual Studio Code",
        "version": "1.92.2",
        "publisher": "Microsoft Corporation"
      }
    ]

---

## Next Steps

- Add CSV export option  
- Add logging of inventory runs  
- Cross-platform support (Linux/macOS via subprocess + package managers)  
- Scheduled runs with history tracking  

---

## Disclaimer

This tool is for **educational and administrative purposes**.  
Use responsibly and only on systems you have authorization to manage.  
