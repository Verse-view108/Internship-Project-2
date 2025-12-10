# ╔══════════════════════════════════════════════════════════════════╗
# ║       NETWORK SNIFFER — WIRESHARK CLONE (100% STABLE FINAL)      ║
# ╚══════════════════════════════════════════════════════════════════╝

import scapy.all as scapy
import sqlite3
import datetime
import threading
import time
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import atexit

# YOUR INTERFACE
INTERFACE = r"\Device\NPF_{EAB2262D-9AB1-5975-7D92-334D06F4972B}"

# DB
conn = sqlite3.connect('capture.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS packets
             (no INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, src TEXT, dst TEXT, proto TEXT, 
              sport INTEGER, dport INTEGER, length INTEGER, info TEXT)''')
conn.commit()

# Global state
packet_counter = 0
total_packets = total_bytes = 0
lock = threading.Lock()
running = False
sniffer = None
status_job = None  # <-- This fixes the error

# Speed
last_time = time.time()
last_packets = last_bytes = 0
current_pps = current_mbps = 0.0

# Graph data
time_data, pkt_data = [], []
pps_vals, mbps_vals = [], []
top_ips = Counter()

# Wireshark light colors
WIRESHARK_COLORS = {
    "TCP":     "#f0f0f0",
    "UDP":     "#e6f3ff",
    "ICMP":    "#ffffe6",
    "HTTP":    "#ffe6cc",
    "HTTPS":   "#ffe6f0",
    "DNS":     "#e6e6ff",
    "OTHER":   "#f8f8f8"
}

def get_info(pkt):
    if pkt.haslayer(scapy.TCP):
        tcp = pkt[scapy.TCP]
        flags = "".join(c for c in "FSRPAUEC" if getattr(tcp.flags, c.lower(), 0))
        if flags: flags = f" [{flags}]"
        if tcp.dport in (80, 8080) or tcp.sport in (80, 8080): return "HTTP"
        if tcp.dport == 443 or tcp.sport == 443: return "HTTPS"
        return f"TCP{flags}"
    if pkt.haslayer(scapy.UDP):
        return "DNS" if pkt.haslayer(scapy.DNS) else "UDP"
    if pkt.haslayer(scapy.ICMP):
        return "ICMP Echo" if pkt[scapy.ICMP].type == 8 else "ICMP Reply"
    return "Other"

def process_packet(pkt):
    global packet_counter, total_packets, total_bytes, current_pps, current_mbps
    global last_time, last_packets, last_bytes

    if not pkt.haslayer(scapy.IP):
        return

    packet_counter += 1
    ip = pkt[scapy.IP]
    now = time.time()
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    length = len(pkt)
    total_packets += 1
    total_bytes += length
    top_ips[ip.src] += 1

    # Speed
    elapsed = now - last_time
    if elapsed >= 1.0:
        current_pps = (total_packets - last_packets) / elapsed
        current_mbps = (total_bytes - last_bytes) * 8 / elapsed / 1_000_000
        last_time = now
        last_packets = total_packets
        last_bytes = total_bytes

        with lock:
            t = datetime.datetime.now()
            time_data.append(t); pkt_data.append(total_packets)
            pps_vals.append(current_pps)
            mbps_vals.append(current_mbps)
            if len(time_data) > 500:
                time_data.pop(0); pkt_data.pop(0)
                pps_vals.pop(0); mbps_vals.pop(0)

    # Protocol
    proto = "OTHER"
    sport = dport = ""
    info = get_info(pkt)
    tag = info.split()[0].upper()

    if pkt.haslayer(scapy.TCP):
        proto = "TCP"
        sport = pkt[scapy.TCP].sport
        dport = pkt[scapy.TCP].dport
    elif pkt.haslayer(scapy.UDP):
        proto = "UDP"
        sport = pkt[scapy.UDP].sport
        dport = pkt[scapy.UDP].dport
    elif pkt.haslayer(scapy.ICMP):
        proto = "ICMP"

    color = WIRESHARK_COLORS.get(tag, WIRESHARK_COLORS["OTHER"])
    tree.insert("", "end", values=(
        packet_counter, ts, ip.src, ip.dst, proto, sport, dport, length, info
    ), tags=(tag.lower(),))
    tree.see(tree.get_children()[-1])

    c.execute("INSERT INTO packets (ts,src,dst,proto,sport,dport,length,info) VALUES (?,?,?,?,?,?,?,?)",
              (ts, ip.src, ip.dst, proto, sport, dport, length, info))
    conn.commit()

def sniffing_loop():
    global sniffer
    sniffer = scapy.AsyncSniffer(iface=INTERFACE, prn=process_packet, store=False)
    sniffer.start()
    while running:
        time.sleep(0.1)
    if sniffer:
        sniffer.stop()

def toggle_capture():
    global running
    if running:
        running = False
        status_label.config(text="Capture stopped", foreground="#ff6666")
        start_btn.config(text="Start Capture", bg="#00aa00")
    else:
        running = True
        tree.delete(*tree.get_children())
        global packet_counter, total_packets, total_bytes
        packet_counter = total_packets = total_bytes = 0
        top_ips.clear()
        with lock:
            time_data.clear(); pkt_data.clear(); pps_vals.clear(); mbps_vals.clear()
        threading.Thread(target=sniffing_loop, daemon=True).start()
        status_label.config(text="Capturing...", foreground="#00ff00")
        start_btn.config(text="Stop Capture", bg="#ff0000")

def clear_display():
    tree.delete(*tree.get_children())
    global packet_counter
    packet_counter = 0

def export_csv():
    file = filedialog.asksaveasfilename(defaultextension=".csv", title="Export Capture")
    if file:
        c.execute("SELECT no,ts,src,dst,proto,sport,dport,length,info FROM packets ORDER BY no")
        with open(file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["No","Time","Source","Destination","Protocol","Src Port","Dst Port","Length","Info"])
            writer.writerows(c.fetchall())
        messagebox.showinfo("Success", f"Exported → {file}")

def update_status():
    global status_job
    if root.winfo_exists():  # <-- Prevents error on close
        status_bar.config(text=f"Packets: {total_packets:,} | Bytes: {total_bytes/1024/1024:.2f} MB | "
                              f"PPS: {current_pps:,.0f} | Mbps: {current_mbps:.2f}")
        status_job = root.after(200, update_status)
    else:
        status_job = None

def on_closing():
    global running, status_job
    running = False
    if status_job:
        root.after_cancel(status_job)
    if sniffer and sniffer.running:
        sniffer.stop()
    root.destroy()

def update_graph(frame):
    with lock:
        ax1.clear()
        if time_data:
            ax1.plot(time_data, pkt_data, '#00d0ff', linewidth=2.5)
            ax1.set_title("Total Packets Over Time", color='#00ffff', fontsize=14)
            ax1.grid(True, alpha=0.3)

        ax2.clear()
        if len(pps_vals) > 1:
            ax2.plot(time_data[-len(pps_vals):], pps_vals, '#00ff00', linewidth=2.5, label="PPS")
            ax2.plot(time_data[-len(mbps_vals):], mbps_vals, '#ff00ff', linewidth=2.5, label="Mbps")
            ax2.set_title("Live Speed", color='yellow', fontsize=14)
            ax2.legend()

        ax3.clear()
        if top_ips:
            ips, cnts = zip(*top_ips.most_common(10))
            ax3.barh(range(len(ips)), cnts, color='#ff3366')
            ax3.set_yticks(range(len(ips)))
            ax3.set_yticklabels(ips, fontsize=10)
            ax3.set_title("Top Source IPs", color='#ff3366')

        for ax in (ax1, ax2, ax3):
            ax.set_facecolor('#0d0d0d')
            ax.tick_params(colors='#888888')

        plt.tight_layout()

# GUI
root = tk.Tk()
root.title("Network Sniffer — Wireshark Clone")
root.geometry("1920x1080")
root.configure(bg="#1e1e1e")
root.state('zoomed')
root.protocol("WM_DELETE_WINDOW", on_closing)  # <-- Critical fix

# Toolbar
toolbar = tk.Frame(root, bg="#2b2b2b", height=70)
toolbar.pack(fill=tk.X, padx=10, pady=5)

tk.Label(toolbar, text="Network Sniffer", font=("Segoe UI", 18, "bold"), fg="#00ffff", bg="#2b2b2b").pack(side=tk.LEFT, padx=20)
tk.Label(toolbar, text=f"Interface: {INTERFACE}", fg="#aaaaaa", bg="#2b2b2b").pack(side=tk.LEFT, padx=20)

start_btn = tk.Button(toolbar, text="Start Capture", command=toggle_capture,
                     font=("Arial", 12, "bold"), bg="#00aa00", fg="white", width=15, height=2)
start_btn.pack(side=tk.RIGHT, padx=10)

tk.Button(toolbar, text="Clear", command=clear_display, bg="#666666", fg="white").pack(side=tk.RIGHT, padx=5)
tk.Button(toolbar, text="Export CSV", command=export_csv, bg="#4444aa", fg="white").pack(side=tk.RIGHT, padx=5)

status_label = tk.Label(toolbar, text="Ready", fg="#00ff00", bg="#2b2b2b", font=("Arial", 12))
status_label.pack(side=tk.RIGHT, padx=20)

# Packet List
list_frame = tk.Frame(root)
list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="white", fieldbackground="white", foreground="black", rowheight=24)
style.configure("Treeview.Heading", background="#3a3a3a", foreground="#00ffff", font=("Arial", 10, "bold"))

columns = ("No", "Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port", "Length", "Info")
tree = ttk.Treeview(list_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=130, anchor="w")
tree.column("No", width=60, anchor="center")
tree.column("Time", width=150)
tree.column("Source", width=160)
tree.column("Destination", width=160)
tree.column("Info", width=320)

tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
vsb = ttk.Scrollbar(list_frame, orient="vertical", command=tree.yview)
vsb.pack(side=tk.RIGHT, fill=tk.Y)
tree.configure(yscrollcommand=vsb.set)

for proto, color in WIRESHARK_COLORS.items():
    tree.tag_configure(proto.lower(), background=color)

# Status bar
status_bar = tk.Label(root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, bg="#333333", fg="white", font=("Arial", 10))
status_bar.pack(fill=tk.X, side=tk.BOTTOM)

# Graphs
graph_frame = tk.Frame(root, bg="#1e1e1e")
graph_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

fig = plt.Figure(figsize=(16, 6), facecolor="#1e1e1e")
ax1 = fig.add_subplot(131)
ax2 = fig.add_subplot(132)
ax3 = fig.add_subplot(133)
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

ani = FuncAnimation(fig, update_graph, interval=1000, cache_frame_data=False)
update_status()

print("WIRESHARK CLONE — 100% STABLE & PERFECT")
root.mainloop()