import socket
import subprocess
import ipaddress
import os
import struct
from tkinter import *
from tkinter import ttk, messagebox
import threading
from threading import Thread
import time

def port_scanner(tab_frame):
    def scan():
        scan_button.config(state=DISABLED)
        remote_host = entry_host.get()
        result_text.delete(1.0, END)
        if not remote_host:
            messagebox.showerror("Input Error", "Please enter a host to scan.")
            scan_button.config(state=NORMAL)
            return
        
        try:
            remote_server_ip = socket.gethostbyname(remote_host)
            result_text.insert(END, f"Scanning {remote_server_ip}...\n")
            for port in (20, 21, 22, 80, 443):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((remote_server_ip, port))
                if result == 0:
                    info = socket.getservbyport(port)
                    result_text.insert(END, f"Port {port}: Open ({info})\n")
                else:
                    result_text.insert(END, f"Port {port}: Closed\n")
                sock.close()
            result_text.insert(END, "Scanning Completed.\n")
        except Exception as e:
            result_text.insert(END, f"Error: {e}\n")
        finally:
            scan_button.config(state=NORMAL)
            entry_host.delete(0, END)

    Label(tab_frame, text="Enter Host to Scan:").pack(pady=5)
    entry_host = Entry(tab_frame, width=30)
    entry_host.pack(pady=5)
    scan_button = Button(tab_frame, text="Scan", command=lambda: Thread(target=scan).start())
    scan_button.pack(pady=5)
    result_text = Text(tab_frame, height=15, width=70)
    result_text.pack(pady=5)

def ip_scanner(tab_frame):
    def scan():
        stop_flag.clear()  # Reset the stop_flag when starting a new scan
        scan_button.config(state=DISABLED)
        stop_button.config(state=NORMAL)
        network = entry_network.get().strip()
        result_text.delete(1.0, END)
        if not network:
            messagebox.showerror("Input Error", "Please enter a network address in CIDR format (e.g., 10.5.117.0/24).")
            scan_button.config(state=NORMAL)
            return
        
        try:
            ip_net = ipaddress.ip_network(network, strict=False)
            result_text.insert(END, f"Scanning network {network}...\n")
            for host in ip_net.hosts():
                if stop_flag.is_set():  # Check if stop is requested
                    result_text.insert(END, "Scanning Stopped.\n")
                    break
                response = os.system(f"ping -n 1 -w 1 {host} >nul")
                if response == 0:
                    result_text.insert(END, f"{host}: Online\n")
                else:
                    result_text.insert(END, f"{host}: Offline\n")
            result_text.insert(END, "Scanning Completed.\n")
        except ValueError:
            result_text.insert(END, "Invalid CIDR format. Use something like 10.5.117.0/24.\n")
        finally:
            scan_button.config(state=NORMAL)
            entry_network.delete(0, END)

    def stop_scan():
        stop_flag.set()

    stop_flag = threading.Event()  # Used to stop the scanning process

    Label(tab_frame, text="Enter Network Address (CIDR):").pack(pady=5)
    entry_network = Entry(tab_frame, width=30)
    entry_network.pack(pady=5)
    scan_button = Button(tab_frame, text="Scan", command=lambda: Thread(target=scan).start())
    scan_button.pack(pady=5)
    stop_button = Button(tab_frame, text="Stop", command=stop_scan, state=DISABLED)
    stop_button.pack(pady=5)
    result_text = Text(tab_frame, height=15, width=70)
    result_text.pack(pady=5)

def send_ping(tab_frame):
    def ping():
        ping_button.config(state=DISABLED)
        ip = entry_ip.get()
        result_text.delete(1.0, END)
        if not ip:
            messagebox.showerror("Input Error", "Please enter an IP address or hostname.")
            ping_button.config(state=NORMAL)
            return
        
        try:
            result = subprocess.run(
                ["ping", "-n", "4", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                result_text.insert(END, f"Ping results for {ip}:\n")
                result_text.insert(END, result.stdout)
            else:
                result_text.insert(END, f"Ping to {ip} failed:\n")
                result_text.insert(END, result.stderr)
        except Exception as e:
            result_text.insert(END, f"Error: {e}\n")
        finally:
            ping_button.config(state=NORMAL)
            entry_ip.delete(0, END)

    Label(tab_frame, text="Enter IP Address/Hostname:").pack(pady=5)
    entry_ip = Entry(tab_frame, width=30)
    entry_ip.pack(pady=5)
    ping_button = Button(tab_frame, text="Ping", command=lambda: Thread(target=ping).start())
    ping_button.pack(pady=5)
    result_text = Text(tab_frame, height=15, width=70)
    result_text.pack(pady=5)

def packet_sniffer(tab_frame):
    def start_sniffer():
        stop_flag.clear()  # Reset the stop_flag when starting new sniffing
        sniff_button.config(state=DISABLED)
        stop_sniff_button.config(state=NORMAL)

        def sniff():
            captured_packets = set()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                s.bind((socket.gethostbyname(socket.gethostname()), 0))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

                while True:
                    if stop_flag.is_set():  # Check if stop is requested
                        result_text.insert(END, "Sniffing Stopped.\n")
                        break
                    packet = s.recvfrom(65565)[0]
                    ip_header = packet[0:20]
                    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                    version_ihl = iph[0]
                    version = version_ihl >> 4
                    s_addr = socket.inet_ntoa(iph[8])
                    d_addr = socket.inet_ntoa(iph[9])
                    packet_info = f"Source: {s_addr}, Dest: {d_addr}"
                    if packet_info not in captured_packets:
                        result_text.insert(END, f"Version: {version}, Source: {s_addr}, Dest: {d_addr}\n")
                        captured_packets.add(packet_info)
            except Exception as e:
                result_text.insert(END, f"Error: {e}\n")
            finally:
                sniff_button.config(state=NORMAL)
                stop_sniff_button.config(state=DISABLED)

        Thread(target=sniff, daemon=True).start()

    def stop_sniff():
        stop_flag.set()

    stop_flag = threading.Event()  # Used to stop sniffing

    sniff_button = Button(tab_frame, text="Start Sniffing", command=start_sniffer)
    sniff_button.pack(pady=5)
    stop_sniff_button = Button(tab_frame, text="Stop Sniffing", command=stop_sniff, state=DISABLED)
    stop_sniff_button.pack(pady=5)
    result_text = Text(tab_frame, height=15, width=70)
    result_text.pack(pady=5)

def main_app():
    root = Tk()
    root.title("Volkan Network Tools")
    root.geometry("800x600")

    style = ttk.Style()
    style.configure("TNotebook", tabposition='n')
    style.theme_use('clam')

    notebook = ttk.Notebook(root)
    notebook.pack(expand=True, fill="both")

    port_scanner_tab = Frame(notebook)
    ip_scanner_tab = Frame(notebook)
    send_ping_tab = Frame(notebook)
    packet_sniffer_tab = Frame(notebook)

    notebook.add(port_scanner_tab, text="Port Scanner")
    notebook.add(ip_scanner_tab, text="IP Scanner")
    notebook.add(send_ping_tab, text="Send Ping")
    notebook.add(packet_sniffer_tab, text="Packet Sniffer")

    port_scanner(port_scanner_tab)
    ip_scanner(ip_scanner_tab)
    send_ping(send_ping_tab)
    packet_sniffer(packet_sniffer_tab)

    root.mainloop()

if __name__ == "__main__":
    main_app()
