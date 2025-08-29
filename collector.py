import argparse
import csv
import getpass
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import winreg
except ImportError:
    print("[ERROR] This tool runs on Windows (needs winreg).", file=sys.stderr)
    sys.exit(1)

UNINSTALL_SUBKEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"

V64 = winreg.KEY_WOW64_64KEY
V32 = winreg.KEY_WOW64_32KEY
READ = winreg.KEY_READ

def get_reg_value(key, name, default=None):
    try:
        val, _ = winreg.QueryValueEx(key, name)
        return val
    except FileNotFoundError:
        return default
    except OSError:
        return default

def parse_install_date(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    s = str(s)
    if len(s) == 8 and s.isdigit():
        return f"{s[0:4]}-{s[4:6]}-{s[6:8]}"
    return s

def safe_int(x) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None

def enumerate_uninstall(hive, view_flag, scope: str, view_name: str, include_system: bool):
    results = []
    try:
        root = winreg.OpenKey(hive, UNINSTALL_SUBKEY, 0, READ | view_flag)
    except FileNotFoundError:
        return results

    i = 0
    while True:
        try:
            sub = winreg.EnumKey(root, i)
            i += 1
        except OSError:
            break

        path = UNINSTALL_SUBKEY + "\\" + sub
        try:
            k = winreg.OpenKey(hive, path, 0, READ | view_flag)
        except OSError:
            continue

        display_name = get_reg_value(k, "DisplayName")
        system_component = get_reg_value(k, "SystemComponent", 0)
        if system_component in (1, "1") and not include_system:
            continue
        if not display_name:
            # Skip entries with no visible name (unless include_system)
            if not include_system:
                continue

        rec = {
            "name": display_name,
            "version": get_reg_value(k, "DisplayVersion"),
            "publisher": get_reg_value(k, "Publisher"),
            "install_date": parse_install_date(get_reg_value(k, "InstallDate")),
            "estimated_size_kb": safe_int(get_reg_value(k, "EstimatedSize")),
            "install_location": get_reg_value(k, "InstallLocation"),
            "uninstall_string": get_reg_value(k, "UninstallString"),
            "release_type": get_reg_value(k, "ReleaseType"),
            "windows_installer": get_reg_value(k, "WindowsInstaller"),
            "scope": scope,                # Machine / User
            "view": view_name,             # 64 / 32
            "source_key": path
        }
        results.append(rec)
    return results

def collect_registry(include_system: bool):
    out = []
    out += enumerate_uninstall(winreg.HKEY_LOCAL_MACHINE, V64, "Machine", "64", include_system)
    out += enumerate_uninstall(winreg.HKEY_LOCAL_MACHINE, V32, "Machine", "32", include_system)
    out += enumerate_uninstall(winreg.HKEY_CURRENT_USER,  V64, "User",    "64", include_system)
    out += enumerate_uninstall(winreg.HKEY_CURRENT_USER,  V32, "User",    "32", include_system)
    return out

def collect_store_apps():
    # Optional UWP/Store apps via PowerShell (no extra deps). Best-effort.
    try:
        ps = [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-Command",
            "Get-AppxPackage | Select-Object Name, PackageFullName, Publisher, Version | ConvertTo-Json -Depth 2"
        ]
        cp = subprocess.run(ps, capture_output=True, text=True, timeout=30)
        if cp.returncode != 0 or not cp.stdout.strip():
            return []
        data = json.loads(cp.stdout)
        # data may be dict or list
        items = data if isinstance(data, list) else [data]
        out = []
        for it in items:
            out.append({
                "name": it.get("Name"),
                "version": it.get("Version"),
                "publisher": it.get("Publisher"),
                "package_full_name": it.get("PackageFullName"),
                "scope": "User",
                "view": "Store",
                "source_key": "AppxPackage"
            })
        return out
    except Exception:
        return []

def host_metadata():
    from platform import platform, version, release, machine
    return {
        "hostname": socket.gethostname(),
        "collected_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform(),
        "os_release": release(),
        "os_version": version(),
        "arch": machine(),
    }

def write_json(path: Path, records: list, meta: dict):
    payload = {"_meta": meta, "items": records}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

def write_csv(path: Path, records: list):
    if not records:
        path.write_text("", encoding="utf-8")
        return
    fields = sorted({k for r in records for k in r.keys()})
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow(r)

def key_for(rec: dict):
    # Simple identity for diff: (name, publisher, scope)
    return (rec.get("name") or "", rec.get("publisher") or "", rec.get("scope") or "")

def load_inv(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("items") if isinstance(data, dict) and "items" in data else data

def diff_inventories(old_items: list, new_items: list):
    old_map = {key_for(r): r for r in old_items}
    new_map = {key_for(r): r for r in new_items}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    added = [new_map[k] for k in sorted(new_keys - old_keys)]
    removed = [old_map[k] for k in sorted(old_keys - new_keys)]

    changed = []
    inter = old_keys & new_keys
    for k in inter:
        o = old_map[k]
        n = new_map[k]
        if (o.get("version") or "") != (n.get("version") or ""):
            changed.append({"name": n.get("name"), "publisher": n.get("publisher"),
                            "scope": n.get("scope"), "from": o.get("version"), "to": n.get("version")})
    return added, removed, changed

def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def _log_path(log_dir: str, kind: str) -> str:
    """
    kind: 'jsonl' or 'txt'
    File is rotated daily: logs/2025-08-25.jsonl
    """
    _ensure_dir(log_dir)
    stamp = datetime.now().strftime("%Y-%m-%d")
    ext = "jsonl" if kind == "jsonl" else "log"
    return os.path.join(log_dir, f"{stamp}.{ext}")

def write_run_log(*, args, out_path: str, out_format: str, count: int,
                  started: float, ended: float, error: str | None = None) -> None:
    rec = {
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "host": socket.gethostname(),
        "user": getpass.getuser(),
        "duration_s": round(ended - started, 3),
        "output_file": out_path,
        "output_format": out_format,
        "record_count": count,
        "status": "error" if error else "ok",
        "error": error,
        "log_dir": args.log_dir,
        "log_format": args.log_format,
        "cmd": " ".join(os.sys.argv),
    }
    path = _log_path(args.log_dir, args.log_format)
    if args.log_format == "jsonl":
        line = json.dumps(rec, ensure_ascii=False)
    else:
        line = (f"{rec['ts']} host={rec['host']} user={rec['user']} "
                f"status={rec['status']} count={count} dur={rec['duration_s']}s "
                f"out='{out_path}' fmt={out_format}" + (f" err='{error}'" if error else ""))
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")

def parse_args():
    ap = argparse.ArgumentParser(description="Software Inventory Collector (Windows)")
    ap.add_argument("--json", help="Write inventory to JSON file")
    ap.add_argument("--csv", help="Write inventory to CSV file")
    ap.add_argument("--include-system", action="store_true", help="Include system components (hidden entries)")
    ap.add_argument("--include-store", action="store_true", help="Include Microsoft Store (Appx) apps")
    ap.add_argument("--log-dir", default="logs", help="Directory to write run logs (default: logs)")
    ap.add_argument("--log-format", choices=["jsonl", "txt"], default="jsonl", help="Run log format (default: jsonl)")
    ap.add_argument("--no-console", action="store_true", help="(Reserved) suppress console prints")
    ap.add_argument("--diff", nargs=2, metavar=("OLD.json", "NEW.json"),
                    help="Compare two JSON inventories and print added/removed/changed")
    return ap.parse_args()

def _outputs_from_args(args) -> tuple[str, str]:
    """
    Return (out_path, out_fmt) for logging.
    - If both JSON and CSV were written, join with ';' and set format 'json,csv'.
    - If neither was requested, we log 'none'.
    """
    outs = []
    if args.json:
        outs.append(("json", str(Path(args.json).expanduser().resolve())))
    if args.csv:
        outs.append(("csv", str(Path(args.csv).expanduser().resolve())))
    if not outs:
        return ("-", "none")
    if len(outs) == 1:
        return (outs[0][1], outs[0][0])
    # both
    return (";".join(p for _, p in outs), "json,csv")


def main():
    args = parse_args()

    # If doing a diff, do it and exit (no run log for diffs by design).
    if args.diff:
        old_path = Path(args.diff[0]).expanduser().resolve()
        new_path = Path(args.diff[1]).expanduser().resolve()
        old_items = load_inv(old_path)
        new_items = load_inv(new_path)
        added, removed, changed = diff_inventories(old_items, new_items)

        print("\n=== Inventory Diff ===")
        print(f"Added   : {len(added)}")
        print(f"Removed : {len(removed)}")
        print(f"Changed : {len(changed)}\n")

        if added:
            print("Added:")
            for a in added[:50]:
                print(f"  + {a.get('name')}  {a.get('version')}  [{a.get('scope')}/{a.get('view')}]")
        if removed:
            print("\nRemoved:")
            for r in removed[:50]:
                print(f"  - {r.get('name')}  {r.get('version')}  [{r.get('scope')}/{r.get('view')}]")
        if changed:
            print("\nChanged (version):")
            for c in changed[:100]:
                print(f"  * {c['name']}  {c['from']} -> {c['to']}  [{c['scope']}]")
        print()
        return

    started = time.perf_counter()
    error_msg = None
    count = 0

    try:
        # Collect current inventory
        items = collect_registry(include_system=args.include_system)
        if args.include_store:
            items.extend(collect_store_apps())

        # Sort for stable output
        items.sort(key=lambda r: ((r.get("name") or "").lower(),
                                  (r.get("publisher") or "").lower()))
        count = len(items)
        meta = host_metadata()
        print(f"[OK] Collected {count} entries on {meta['hostname']}.")

        # Write outputs
        if args.json:
            out = Path(args.json).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            write_json(out, items, meta)
            print(f"[OK] Wrote JSON: {out}")
        if args.csv:
            out = Path(args.csv).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            write_csv(out, items)
            print(f"[OK] Wrote CSV : {out}")

        # If no output flags, print a small preview
        if not args.json and not args.csv:
            for r in items[:25]:
                ver = r.get("version") or "-"
                pub = r.get("publisher") or "-"
                print(f"  {r.get('name')}  {ver}  ({pub})  [{r.get('scope')}/{r.get('view')}]")

    except Exception as e:
        error_msg = str(e)
        raise
    finally:
        ended = time.perf_counter()
        out_path, out_fmt = _outputs_from_args(args)
        write_run_log(
            args=args,
            out_path=out_path,
            out_format=out_fmt,
            count=count,
            started=started,
            ended=ended,
            error=error_msg,
        )

if __name__ == "__main__":
    main()
