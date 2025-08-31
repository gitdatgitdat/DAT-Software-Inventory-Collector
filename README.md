# DAT Software Inventory Collector

A lightweight Python utility to collect and export a list of installed software on a Windows machine.  
Built as a system administration learning project to practice automation, logging, and inventory management.

---

## Features

- Collects installed software via Windows registry  
- Optional Microsoft Store (AppX) enumeration  
- Outputs results to JSON or CSV  
- Run logging (daily rotated jsonl or txt)  
- History snapshots with quick diffs  
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

Optons:
- Write JSON: --json PATH  
- Write CSV: --csv PATH  
- Include hidden/system entries: --include-system  
- Include Microsoft Store apps: --include-store  
- Run logging: --log-dir logs --log-format jsonl|txt  
- Save timestamped snapshot: --history [--history-dir history]  
- Diff against latest snapshot: --diff-last  
- Compare two saved inventories: --diff OLD.json NEW.json  

Example input:
- JSON
`python collector.py --json out\inventory.json`

- CSV  
python collector.py --csv out\inventory.csv

- JSON + CSV + history + auto-diff vs previous snapshot  
`python collector.py --json out\full.json --csv out\full.csv --history --diff-last`

- Two-file diff  
`python collector.py --diff history\2025-08-28_HOST.json history\2025-08-29_HOST.json`

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

## Logging

Runs are logged by day to the logs directory.  

Switch between json and txt with:  
`--log-format jsonl`  
or  
`--log-format txt`  

---

## History and Differentials

Save a timestamped snapshot with:  
`--history [--history-dir history]`

Quickly compare run with the previous snapshot:
`--diff-last`

Or compare two runs with:
`--diff OLD.json NEW.json`

## Next Steps

- Add a tag ("monthly audit) and have it included in filename/logs  
- Optional history retention (Keep the last X amount of snapshots)  
- Cross-platform support (Linux/macOS via subprocess + package managers)    
- Export hashes of output for integrity tracking  

---

## Disclaimer

This tool is for **educational and administrative purposes**.  
Use responsibly and only on systems you have authorization to manage.  
