import os
import signal
import subprocess
import sys

def get_pid(process_name):
    try:
        # Using pgrep is more reliable than parsing ps output manually
        output = subprocess.check_output(["pgrep", "-f", process_name])
        pids = output.decode().strip().split("n")
        return [int(pid) for pid in pids]
    except subprocess.CalledProcessError:
        return []

def main():
    process_name = "Rust_US"
    pids = get_pid(process_name)

    if not pids:
        print(f"[!] Error: No process found matching '{process_name}'")
        sys.exit(1)

    # We send the signal to the first match, or all matches if preferred
    for pid in pids:
        try:
            print(f"[*] Sending SIGHUP to {process_name} (PID: {pid})...")
            os.kill(pid, signal.SIGHUP)
            print("[+] Signal sent successfully.")
        except PermissionError:
            print(f"[!] Error: Insufficient permissions to signal PID {pid}. Try running with sudo.")
        except ProcessLookupError:
            print(f"[!] Error: Process {pid} disappeared before signal could be sent.")
        except Exception as e:
            print(f"[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
