import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import re

stop_event = threading.Event()

def resolve_host(ip_or_domain):
    """ Resolve domain names to IP addresses """
    try:
        ip = socket.gethostbyname(ip_or_domain)
        return ip
    except socket.gaierror:
        return None

def scanHost(ip_or_domain, startPort, endPort, output_text, protocol, timeout, progress_var):
    """ Starts a TCP/UDP scan on a given IP address or domain """
    ip = resolve_host(ip_or_domain)
    if ip is None:
        output_text.insert(tk.END, f'[!] Unable to resolve {ip_or_domain}\n', 'error')
        return

    output_text.insert(tk.END, f'[*] Starting {protocol.upper()} port scan on host {ip_or_domain} ({ip})\n', 'info')
    tcp_udp_scan(ip, startPort, endPort, output_text, protocol, timeout, progress_var)
    output_text.insert(tk.END, f'[+] {protocol.upper()} scan on host {ip_or_domain} ({ip}) complete\n', 'info')

def scanRange(network, startPort, endPort, output_text, protocol, timeout, progress_var):
    """ Starts a TCP/UDP scan on a given IP address range """
    output_text.insert(tk.END, f'[*] Starting {protocol.upper()} port scan on network {network}.0\n', 'info')

    total_hosts = 254
    for host in range(1, 255):
        if stop_event.is_set():
            break
        ip = network + '.' + str(host)
        tcp_udp_scan(ip, startPort, endPort, output_text, protocol, timeout, progress_var, total_hosts)

    output_text.insert(tk.END, f'[+] {protocol.upper()} scan on network {network}.0 complete\n', 'info')

def tcp_udp_scan(ip, startPort, endPort, output_text, protocol, timeout, progress_var, total_hosts=1):
    """ Creates a TCP/UDP socket and attempts to connect via supplied ports """
    open_ports = []
    total_ports = endPort - startPort + 1
    scanned_ports = 0

    for port in range(startPort, endPort + 1):
        if stop_event.is_set():
            break
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            if protocol == 'tcp':
                if not sock.connect_ex((ip, port)):
                    open_ports.append(port)
            else:
                sock.sendto(b'', (ip, port))
                if sock.recvfrom(1024):
                    open_ports.append(port)
            sock.close()
        except Exception:
            pass

        scanned_ports += 1
        progress = (scanned_ports / total_ports) / total_hosts * 100
        progress_var.set(progress)
        root.update_idletasks()

    for port in open_ports:
        output_text.insert(tk.END, f'[+] {ip}:{port}/{protocol.upper()} Open\n', 'open')

def start_scan():
    stop_event.clear()
    ip_or_domain = ip_entry.get().strip()
    start_port = int(start_port_entry.get().strip())
    end_port = int(end_port_entry.get().strip())
    protocol = protocol_var.get()
    timeout = float(timeout_entry.get().strip())
    output_text.delete(1.0, tk.END)
    progress_var.set(0)

    if not validate_ip_or_domain(ip_or_domain):
        messagebox.showerror("Invalid Input", "Please enter a valid IP address or domain name.")
        return

    scan_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    if range_scan_var.get():
        if re.match(r"^\d{1,3}(\.\d{1,3}){2}$", ip_or_domain):  # Ensure network range is valid
            threading.Thread(target=scanRange, args=(ip_or_domain, start_port, end_port, output_text, protocol, timeout, progress_var)).start()
        else:
            messagebox.showerror("Invalid Network Range", "Please enter a valid network range in the format: X.X.X")
            stop_scan()
    else:
        threading.Thread(target=scanHost, args=(ip_or_domain, start_port, end_port, output_text, protocol, timeout, progress_var)).start()

def stop_scan():
    stop_event.set()
    scan_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

def validate_ip_or_domain(ip_or_domain):
    """ Validates if the input is a valid IP address or domain name """
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"  # First character of the domain
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"  # Sub domain + hostname
        r"+[a-zA-Z]{2,6}$"  # First level domain
    )
    return ip_pattern.match(ip_or_domain) or domain_pattern.match(ip_or_domain)

def save_results():
    results = output_text.get(1.0, tk.END)
    if results.strip():
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if save_path:
            with open(save_path, 'w') as file:
                file.write(results)
            messagebox.showinfo("Saved", "Results saved successfully.")
    else:
        messagebox.showwarning("No Results", "No results to save.")

# GUI setup
root = tk.Tk()
root.title("Port Scanner")

mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

ttk.Label(mainframe, text="IP Address / Domain:").grid(column=0, row=0, sticky=tk.W)
ip_entry = ttk.Entry(mainframe, width=20)
ip_entry.grid(column=1, row=0, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Start Port:").grid(column=0, row=1, sticky=tk.W)
start_port_entry = ttk.Entry(mainframe, width=10)
start_port_entry.grid(column=1, row=1, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="End Port:").grid(column=0, row=2, sticky=tk.W)
end_port_entry = ttk.Entry(mainframe, width=10)
end_port_entry.grid(column=1, row=2, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Protocol:").grid(column=0, row=3, sticky=tk.W)
protocol_var = tk.StringVar(value='tcp')
protocol_option = ttk.OptionMenu(mainframe, protocol_var, 'tcp', 'tcp', 'udp')
protocol_option.grid(column=1, row=3, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="Timeout (seconds):").grid(column=0, row=4, sticky=tk.W)
timeout_entry = ttk.Entry(mainframe, width=10)
timeout_entry.grid(column=1, row=4, sticky=(tk.W, tk.E))
timeout_entry.insert(0, "0.01")

range_scan_var = tk.BooleanVar()
range_scan_check = ttk.Checkbutton(mainframe, text="Scan Range", variable=range_scan_var)
range_scan_check.grid(column=1, row=5, sticky=tk.W)

scan_button = ttk.Button(mainframe, text="Start Scan", command=start_scan)
scan_button.grid(column=1, row=6, sticky=tk.W)

stop_button = ttk.Button(mainframe, text="Stop Scan", command=stop_scan, state=tk.DISABLED)
stop_button.grid(column=1, row=7, sticky=tk.W)

save_button = ttk.Button(mainframe, text="Save Results", command=save_results)
save_button.grid(column=1, row=8, sticky=tk.W)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(mainframe, variable=progress_var, maximum=100)
progress_bar.grid(column=0, row=9, columnspan=2, sticky=(tk.W, tk.E))

output_text = scrolledtext.ScrolledText(mainframe, width=50, height=20)
output_text.grid(column=0, row=10, columnspan=2, sticky=(tk.W, tk.E))

output_text.tag_config('info', foreground='blue')
output_text.tag_config('open', foreground='green')
output_text.tag_config('error', foreground='red')

for child in mainframe.winfo_children():
    child.grid_configure(padx=5, pady=5)


if __name__ == '__main__':
    socket.setdefaulttimeout(0.01)
    root.mainloop()
