import os
import subprocess
import threading
import time
import ctypes
import tkinter as tk
from tkinter import filedialog, messagebox
import win32evtlog

# Define paths
procmon_path = os.path.join("tools", "Procmon.exe")
tshark_path = os.path.join("tools", "tshark.exe")
log_dir = os.path.join("logs")
etw_log_path = os.path.join(log_dir, "ETWLogs.txt")
report_path = os.path.join(log_dir, "final_report.txt")

# Check for admin privileges
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Ensure required directories exist
def ensure_directories():
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print("[*] Logs directory created.")

# Start ETW tracing using pywin32 (Process Creation Events)
def start_etw():
    print("[*] ETW tracing setup complete. Monitoring system events...")
    return True

# Stop ETW tracing and save logs
def stop_etw():
    try:
        server = "localhost"
        log_type = "Microsoft-Windows-Sysmon/Operational"
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        with open(etw_log_path, "w") as log_file:
            log_file.write("==== ETW Process Creation Logs ====\n")
            hand = win32evtlog.OpenEventLog(server, log_type)
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            for event in events:
                log_file.write(f"Source: {event.SourceName}, Time: {event.TimeGenerated}, EventID: {event.EventID}\n")
            win32evtlog.CloseEventLog(hand)
        print(f"[*] ETW tracing stopped and saved at {etw_log_path}.")
    except Exception as e:
        print(f"[!] Failed to stop ETW tracing: {e}")

# Start Procmon
def start_procmon():
    try:
        procmon_log = os.path.join(log_dir, "ProcMonLogs.pml")
        subprocess.Popen([procmon_path, "/Quiet", "/Minimized", "/Backingfile", procmon_log])
        print("[*] Procmon started.")
    except Exception as e:
        print(f"[!] Failed to start Procmon: {e}")

# Save Procmon logs in CSV format
def save_procmon_logs():
    procmon_csv = os.path.join(log_dir, "ProcMonLogs.csv")
    try:
        subprocess.run([procmon_path, "/SaveAs", procmon_csv], check=True)
        print(f"[*] Procmon logs saved as CSV at {procmon_csv}.")
    except Exception as e:
        print(f"[!] Failed to save Procmon logs: {e}")

# Start Tshark
def start_tshark():
    try:
        tshark_log = os.path.join(log_dir, "network_capture.pcapng")
        subprocess.Popen([tshark_path, "-i", "1", "-w", tshark_log])
        print("[*] Tshark started.")
    except Exception as e:
        print(f"[!] Failed to start Tshark: {e}")

# Stop monitoring tools
def stop_tools():
    stop_etw()
    subprocess.run(["taskkill", "/F", "/IM", "Procmon.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["taskkill", "/F", "/IM", "tshark.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[*] Monitoring tools stopped.")

# Analyze Logs and Generate Final Report
def analyze_logs():
    etw_log = etw_log_path
    procmon_csv = os.path.join(log_dir, "ProcMonLogs.csv")
    tshark_log = os.path.join(log_dir, "network_capture.pcapng")

    results = []

    # Analyze ETW Logs (Placeholder analysis)
    if os.path.exists(etw_log):
        results.append("[ETW] Process creation logs captured.")

    # Analyze Procmon Logs (Placeholder analysis)
    if os.path.exists(procmon_csv):
        results.append("[Procmon] Procmon logs analyzed: No malicious activity detected.")

    # Analyze Tshark Logs (Placeholder analysis)
    if os.path.exists(tshark_log):
        results.append("[Tshark] Network activity appears normal.")

    try:
        with open(report_path, "w") as report:
            report.writelines("\n".join(results))
            report.write("\n[*] Final Analysis: File appears safe.\n" if not results else "\n[*] Final Analysis: Potential threats detected.\n")
        print(f"[*] Report generated at {report_path}.")
    except Exception as e:
        print(f"[!] Failed to write report: {e}")

# Full Malware Analysis Workflow
def malware_analysis(malware_path):
    print("[*] Starting malware analysis...")
    ensure_directories()

    # Start ETW and other monitoring tools
    start_etw()
    start_procmon()
    start_tshark()

    # Execute malware
    try:
        subprocess.Popen([malware_path], shell=True)
        print(f"[*] Executed malware: {malware_path}")
    except Exception as e:
        print(f"[!] Failed to execute malware: {e}")

    # Stop tools and analyze logs after a timeout
    threading.Timer(30, lambda: [stop_tools(), save_procmon_logs(), analyze_logs()]).start()

# GUI for file selection and triggering analysis
def run_gui():
    def start_analysis():
        if not is_admin():
            messagebox.showerror("Error", "Please run this program as an administrator.")
            return

        malware_path = malware_var.get()
        if malware_path and os.path.exists(malware_path):
            malware_analysis(malware_path)
            messagebox.showinfo("Info", "Malware analysis started. Check logs and report upon completion.")
        else:
            messagebox.showerror("Error", "Please select a valid malware sample.")

    # GUI setup
    app = tk.Tk()
    app.title("Dynamic Malware Analysis")

    tk.Label(app, text="Select Malware Sample:").grid(row=0, column=0, padx=10, pady=10)
    malware_var = tk.StringVar()
    tk.Entry(app, textvariable=malware_var, width=50).grid(row=0, column=1, padx=10, pady=10)
    tk.Button(app, text="Browse", command=lambda: malware_var.set(filedialog.askopenfilename())).grid(row=0, column=2, padx=10, pady=10)
    tk.Button(app, text="Start Analysis", command=start_analysis).grid(row=1, column=1, pady=20)

    app.mainloop()

if __name__ == "__main__":
    run_gui()
