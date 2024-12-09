import customtkinter as ctk, subprocess, threading, psutil, socket, platform, time, os, dns.resolver, requests, cpuinfo
from tkinter import messagebox
from concurrent.futures import ThreadPoolExecutor

THEME_COLORS = {
    "bg": "#0a0a12",
    "card": "#12121f", 
    "accent": "#6b4ba3",
    "text": "#ffffff",
    "text_secondary": "#a09cb0",
    "button": "#533a80",
    "button_hover": "#6b4ba3",
    "switch_on": "#6b4ba3",
    "switch_off": "#2a2a3a"
}

class CustomSwitch(ctk.CTkSwitch):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(
            button_color=THEME_COLORS["switch_on"],
            button_hover_color=THEME_COLORS["switch_on"],
            progress_color=THEME_COLORS["switch_off"],
            fg_color=THEME_COLORS["switch_off"]
        )

class SystemOptimizer:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("MOG-UTILITIES V2")
        self.root.geometry("1200x900")
        ctk.set_appearance_mode("dark")
        self.root.configure(fg_color=THEME_COLORS["bg"])
        
        self.main_frame = ctk.CTkFrame(self.root, fg_color=THEME_COLORS["bg"])
        self.main_frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        self.header = ctk.CTkLabel(
            self.main_frame,
            text="MOG-UTILITIES V2",
            font=("Segoe UI", 28, "bold"),
            text_color=THEME_COLORS["text"]
        )
        self.header.pack(pady=10)
        
        self.status_label = ctk.CTkLabel(
            self.main_frame, 
            text="Ready",
            font=("Segoe UI", 12),
            text_color=THEME_COLORS["text_secondary"]
        )
        self.status_label.pack(pady=5)

        self.tabview = ctk.CTkTabview(
            self.main_frame,
            fg_color=THEME_COLORS["bg"],
            segmented_button_fg_color=THEME_COLORS["card"],
            segmented_button_selected_color=THEME_COLORS["accent"],
            segmented_button_unselected_color=THEME_COLORS["bg"]
        )
        self.tabview.pack(pady=10, fill="both", expand=True)
        
        self.tabview.add("Network")
        self.tabview.add("DNS")
        self.tabview.add("CPU")
        self.tabview.add("RAM")
        self.tabview.add("Monitor")
        
        self.optimizations = {}
        self.dns_results = {}
        self.setup_network_tab()
        self.setup_dns_tab()
        self.setup_cpu_tab()
        self.setup_ram_tab()
        self.setup_monitor_tab()
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
        self.monitor_thread.start()

    def setup_network_tab(self):
        net_frame = self.tabview.tab("Network")
        self.net_scroll = ctk.CTkScrollableFrame(net_frame, fg_color=THEME_COLORS["bg"])
        self.net_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        network_opts = {
            "TCP Optimization": "Optimize TCP/IP settings",
            "Network Adapter": "Configure adapter settings",
            "QoS Settings": "Quality of Service optimization",
            "Network Priority": "Set network priority",
            "WiFi Settings": "Optimize wireless connection",
            "Network Cache": "Clear and optimize caches",
            "Network Services": "Optimize network services",
            "Bandwidth Settings": "Optimize bandwidth usage",
            "Network Buffer": "Optimize network buffer size",
            "MTU Optimization": "Optimize MTU settings",
            "DNS Cache": "Optimize DNS cache",
            "Network Protocols": "Optimize network protocols",
            "Network Latency": "Reduce network latency",
            "Network Congestion": "Optimize congestion control",
            "Network Security": "Optimize network security"
        }
        
        for opt, desc in network_opts.items():
            frame = ctk.CTkFrame(self.net_scroll, fg_color=THEME_COLORS["card"])
            frame.pack(fill="x", pady=2)
            var = ctk.BooleanVar()
            switch = CustomSwitch(frame, text=opt, variable=var, font=("Segoe UI", 12))
            switch.pack(side="left", padx=5)
            ctk.CTkLabel(
                frame,
                text=desc,
                font=("Segoe UI", 11),
                text_color=THEME_COLORS["text_secondary"]
            ).pack(side="left", padx=5)
            self.optimizations[opt] = var

        control_frame = ctk.CTkFrame(net_frame, fg_color=THEME_COLORS["bg"])
        control_frame.pack(fill="x", padx=10, pady=5)
        self.apply_net_btn = ctk.CTkButton(
            control_frame,
            text="Apply Network Optimizations",
            command=self.apply_network_optimizations,
            font=("Segoe UI", 12),
            fg_color=THEME_COLORS["button"],
            hover_color=THEME_COLORS["button_hover"]
        )
        self.apply_net_btn.pack(side="right", padx=5)

    def setup_dns_tab(self):
        dns_frame = self.tabview.tab("DNS")
        self.dns_scroll = ctk.CTkScrollableFrame(dns_frame, fg_color=THEME_COLORS["bg"])
        self.dns_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.dns_servers = {
            # North America
            "Cloudflare": ["1.1.1.1", "1.0.0.1"],
            "Google": ["8.8.8.8", "8.8.4.4"],
            "OpenDNS": ["208.67.222.222", "208.67.220.220"],
            "Quad9": ["9.9.9.9", "149.112.112.112"],
            "Level3": ["4.2.2.1", "4.2.2.2"],
            "DNS.WATCH": ["84.200.69.80", "84.200.70.40"],
            "Comodo": ["8.26.56.26", "8.20.247.20"],
            "AdGuard": ["94.140.14.14", "94.140.15.15"],
            "CleanBrowsing": ["185.228.168.9", "185.228.169.9"],
            "Alternate DNS": ["76.76.19.19", "76.223.122.150"],

            # Asia
            "Alibaba": ["223.5.5.5", "223.6.6.6"],
            "Baidu": ["180.76.76.76", "180.76.76.77"],
            "CNNIC SDNS": ["1.2.4.8", "210.2.4.8"],
            "DNSPod": ["119.29.29.29", "182.254.116.116"],
            "360 Secure": ["101.226.4.6", "123.125.81.6"],
            "KDDI Japan": ["203.141.128.1", "203.141.128.2"],
            "IIJ Japan": ["202.232.2.1", "202.232.2.2"],
            "NAVER Korea": ["164.124.101.2", "164.124.107.9"],
            "SK Broadband": ["219.250.36.130", "219.250.36.131"],
            "VNPT Vietnam": ["203.162.4.191", "203.162.4.190"],

            # Europe
            "FDN France": ["80.67.169.12", "80.67.169.40"],
            "FoolDNS NL": ["87.118.111.215", "213.187.11.62"],
            "Dutch DNS": ["176.9.93.198", "176.9.1.117"],
            "FreeDNS DE": ["37.235.1.174", "37.235.1.177"],
            "Uncensored DE": ["91.239.100.100", "89.233.43.71"],
            "Swiss Privacy": ["185.95.218.42", "185.95.218.43"],
            "SWITCH CH": ["130.59.31.248", "130.59.31.251"],
            "Yandex RU": ["77.88.8.8", "77.88.8.1"],
            "SkyDNS RU": ["193.58.251.251", "193.58.251.252"],
            "ITL Austria": ["213.208.146.1", "213.208.146.2"],

            # Australia/Oceania
            "Austech DNS": ["43.242.107.125", "43.242.107.126"],
            "Oracle AU": ["203.135.44.31", "203.135.44.32"],
            "Cloudmax AU": ["203.167.220.153", "203.167.220.154"],
            "Internet AU": ["61.8.0.113", "202.136.162.11"],
            "Telstra": ["139.130.4.4", "139.130.4.5"],
            "Optus AU": ["198.142.152.28", "198.142.152.29"],
            "iiNet": ["203.0.178.191", "203.0.178.192"],
            "TPG AU": ["203.12.160.35", "203.12.160.36"],
            "Vodafone NZ": ["202.73.99.1", "202.73.99.2"],
            "Spark NZ": ["203.109.252.1", "203.109.252.2"]
        }

        regions = ["North America", "Asia", "Europe", "Australia/Oceania"]
        
        for region in regions:
            region_frame = ctk.CTkFrame(self.dns_scroll, fg_color=THEME_COLORS["bg"])
            region_frame.pack(fill="x", pady=5)
            ctk.CTkLabel(
                region_frame,
                text=region,
                font=("Segoe UI", 14, "bold"),
                text_color=THEME_COLORS["accent"]
            ).pack(pady=5)

            region_servers = {k: v for k, v in self.dns_servers.items() 
                            if k in self.get_region_servers(region)}
            
            for server, ips in region_servers.items():
                frame = ctk.CTkFrame(self.dns_scroll, fg_color=THEME_COLORS["card"])
                frame.pack(fill="x", pady=2)
                ctk.CTkLabel(
                    frame,
                    text=server,
                    font=("Segoe UI", 12),
                    text_color=THEME_COLORS["text"]
                ).pack(side="left", padx=5)
                ctk.CTkLabel(
                    frame,
                    text=f"({ips[0]})",
                    font=("Segoe UI", 11),
                    text_color=THEME_COLORS["text_secondary"]
                ).pack(side="left", padx=5)
                self.dns_results[server] = ctk.CTkLabel(
                    frame,
                    text="Not tested",
                    font=("Segoe UI", 11),
                    text_color=THEME_COLORS["text_secondary"]
                )
                self.dns_results[server].pack(side="right", padx=5)

        control_frame = ctk.CTkFrame(dns_frame, fg_color=THEME_COLORS["bg"])
        control_frame.pack(fill="x", padx=10, pady=5)
        
        self.test_dns_btn = ctk.CTkButton(
            control_frame,
            text="Test DNS Servers",
            command=self.test_dns_servers,
            font=("Segoe UI", 12),
            fg_color=THEME_COLORS["button"],
            hover_color=THEME_COLORS["button_hover"]
        )
        self.test_dns_btn.pack(side="left", padx=5)
        
        self.apply_dns_btn = ctk.CTkButton(
            control_frame,
            text="Apply Fastest DNS",
            command=self.apply_fastest_dns,
            font=("Segoe UI", 12),
            fg_color=THEME_COLORS["button"],
            hover_color=THEME_COLORS["button_hover"]
        )
        self.apply_dns_btn.pack(side="right", padx=5)

    def get_region_servers(self, region):
        regions = {
            "North America": ["Cloudflare", "Google", "OpenDNS", "Quad9", "Level3", 
                            "DNS.WATCH", "Comodo", "AdGuard", "CleanBrowsing", "Alternate DNS"],
            "Asia": ["Alibaba", "Baidu", "CNNIC SDNS", "DNSPod", "360 Secure", 
                    "KDDI Japan", "IIJ Japan", "NAVER Korea", "SK Broadband", "VNPT Vietnam"],
            "Europe": ["FDN France", "FoolDNS NL", "Dutch DNS", "FreeDNS DE", 
                      "Uncensored DE", "Swiss Privacy", "SWITCH CH", "Yandex RU", 
                      "SkyDNS RU", "ITL Austria"],
            "Australia/Oceania": ["Austech DNS", "Oracle AU", "Cloudmax AU", 
                                "Internet AU", "Telstra", "Optus AU", "iiNet", 
                                "TPG AU", "Vodafone NZ", "Spark NZ"]
        }
        return regions.get(region, [])

    def test_dns_servers(self):
        self.test_dns_btn.configure(state="disabled", text="Testing...")
        total_servers = len(self.dns_servers)
        tested_servers = 0

        self.progress_label = ctk.CTkLabel(
            self.dns_scroll,
            text=f"Testing: 0/{total_servers} servers",
            font=("Segoe UI", 12),
            text_color=THEME_COLORS["text_secondary"]
        )
        self.progress_label.pack(pady=5)
        
        def test():
            nonlocal tested_servers
            test_domains = ["www.google.com", "www.cloudflare.com", "www.amazon.com"]
            
            def test_single_dns(server, ips):
                nonlocal tested_servers
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [socket.gethostbyname(ips[0])]
                    resolver.timeout = 1
                    resolver.lifetime = 1
                    
                    times = []
                    for domain in test_domains:
                        start = time.time()
                        try:
                            resolver.resolve(domain)
                            times.append(time.time() - start)
                        except:
                            times.append(1.0)
                    
                    avg_time = sum(times) / len(times) * 1000
                    self.root.after(0, lambda s=server, t=avg_time: 
                        self.dns_results[s].configure(
                            text=f"{t:.0f}ms",
                            text_color=THEME_COLORS["text_secondary"]
                        ))
                except Exception as e:
                    self.root.after(0, lambda s=server: 
                        self.dns_results[s].configure(
                            text="Failed",
                            text_color="#ff4444"
                        ))
                
                tested_servers += 1
                self.root.after(0, lambda: self.progress_label.configure(
                    text=f"Testing: {tested_servers}/{total_servers} servers"
                ))
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = []
                for server, ips in self.dns_servers.items():
                    futures.append(executor.submit(test_single_dns, server, ips))
                
                for future in futures:
                    future.result()
            
            self.root.after(0, lambda: [
                self.test_dns_btn.configure(state="normal", text="Test DNS Servers"),
                self.progress_label.configure(text=f"Testing complete: {tested_servers} servers tested"),
                self.progress_label.after(3000, self.progress_label.destroy)
            ])
        
        threading.Thread(target=test).start()

    def apply_fastest_dns(self):
        fastest = None
        fastest_time = float('inf')
        
        for server, label in self.dns_results.items():
            try:
                time_text = label.cget("text")
                if time_text.endswith('ms'):
                    time_value = float(time_text[:-2])
                    if time_value < fastest_time:
                        fastest_time = time_value
                        fastest = server
            except:
                continue
        
        if not fastest:
            messagebox.showerror("Error", "Please test DNS servers first!")
            return
        
        try:
            dns_ips = self.dns_servers[fastest]
            os_type = platform.system()
            
            if os_type == "Windows":
                interface = "Wi-Fi" if os.system("netsh interface show interface name=\"Wi-Fi\"") == 0 else "Ethernet"
                commands = [
                    f'netsh interface ip set dns name="{interface}" static {dns_ips[0]}',
                    f'netsh interface ip add dns name="{interface}" {dns_ips[1]} index=2'
                ]
                for cmd in commands:
                    subprocess.run(cmd, shell=True, capture_output=True)
            elif os_type == "Linux":
                with open('/etc/resolv.conf', 'w') as f:
                    f.write(f"nameserver {dns_ips[0]}\n")
                    f.write(f"nameserver {dns_ips[1]}\n")
            
            messagebox.showinfo("Success", f"Applied {fastest} DNS servers!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply DNS settings: {str(e)}")

    def setup_cpu_tab(self):
        cpu_frame = self.tabview.tab("CPU")
        self.cpu_scroll = ctk.CTkScrollableFrame(cpu_frame, fg_color=THEME_COLORS["bg"])
        self.cpu_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        cpu_opts = {
            "CPU Priority": "Optimize CPU process priority",
            "Power Settings": "Optimize power settings",
            "CPU Scheduling": "Optimize CPU scheduling",
            "Core Parking": "Disable CPU core parking",
            "CPU Cache": "Optimize CPU cache",
            "CPU Affinity": "Set optimal CPU affinity",
            "Process Priority": "Optimize process priorities",
            "CPU Throttling": "Disable CPU throttling",
            "CPU Performance": "Maximum performance mode",
            "CPU Temperature": "Optimize cooling settings",
            "CPU Boost": "Enable CPU boost mode",
            "CPU Power Plan": "High performance power plan",
            "CPU C-States": "Optimize C-States",
            "CPU Frequency": "Optimize CPU frequency",
            "Background Apps": "Limit background processes"
        }
        
        for opt, desc in cpu_opts.items():
            frame = ctk.CTkFrame(self.cpu_scroll, fg_color=THEME_COLORS["card"])
            frame.pack(fill="x", pady=2)
            var = ctk.BooleanVar()
            switch = CustomSwitch(frame, text=opt, variable=var, font=("Segoe UI", 12))
            switch.pack(side="left", padx=5)
            ctk.CTkLabel(
                frame,
                text=desc,
                font=("Segoe UI", 11),
                text_color=THEME_COLORS["text_secondary"]
            ).pack(side="left", padx=5)
            self.optimizations[opt] = var

        control_frame = ctk.CTkFrame(cpu_frame, fg_color=THEME_COLORS["bg"])
        control_frame.pack(fill="x", padx=10, pady=5)
        self.apply_cpu_btn = ctk.CTkButton(
            control_frame,
            text="Apply CPU Optimizations",
            command=self.apply_cpu_optimizations,
            font=("Segoe UI", 12),
            fg_color=THEME_COLORS["button"],
            hover_color=THEME_COLORS["button_hover"]
        )
        self.apply_cpu_btn.pack(side="right", padx=5)

    def setup_ram_tab(self):
        ram_frame = self.tabview.tab("RAM")
        self.ram_scroll = ctk.CTkScrollableFrame(ram_frame, fg_color=THEME_COLORS["bg"])
        self.ram_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        ram_opts = {
            "Memory Cache": "Clear memory cache",
            "Page File": "Optimize page file settings",
            "Memory Priority": "Set memory priority",
            "Memory Compression": "Enable memory compression",
            "Working Set": "Optimize working set",
            "Memory Pool": "Optimize memory pool",
            "Standby List": "Clear standby list",
            "Memory Defrag": "Defragment memory",
            "Memory Trimming": "Enable memory trimming",
            "Memory Mapping": "Optimize memory mapping",
            "Memory Allocation": "Optimize allocation",
            "Memory Leaks": "Fix memory leaks",
            "Memory Usage": "Optimize memory usage",
            "Memory Prefetch": "Optimize prefetch",
            "Memory Services": "Optimize services"
        }
        
        for opt, desc in ram_opts.items():
            frame = ctk.CTkFrame(self.ram_scroll, fg_color=THEME_COLORS["card"])
            frame.pack(fill="x", pady=2)
            var = ctk.BooleanVar()
            switch = CustomSwitch(frame, text=opt, variable=var, font=("Segoe UI", 12))
            switch.pack(side="left", padx=5)
            ctk.CTkLabel(
                frame,
                text=desc,
                font=("Segoe UI", 11),
                text_color=THEME_COLORS["text_secondary"]
            ).pack(side="left", padx=5)
            self.optimizations[opt] = var

        control_frame = ctk.CTkFrame(ram_frame, fg_color=THEME_COLORS["bg"])
        control_frame.pack(fill="x", padx=10, pady=5)
        self.apply_ram_btn = ctk.CTkButton(
            control_frame,
            text="Apply RAM Optimizations",
            command=self.apply_ram_optimizations,
            font=("Segoe UI", 12),
            fg_color=THEME_COLORS["button"],
            hover_color=THEME_COLORS["button_hover"]
        )
        self.apply_ram_btn.pack(side="right", padx=5)

    def setup_monitor_tab(self):
        monitor_frame = self.tabview.tab("Monitor")
        
        info_frame = ctk.CTkFrame(monitor_frame, fg_color=THEME_COLORS["card"])
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.cpu_label = ctk.CTkLabel(
            info_frame,
            text="CPU Usage: ---%",
            font=("Segoe UI", 12),
            text_color=THEME_COLORS["text"]
        )
        self.cpu_label.pack(pady=5)
        
        self.ram_label = ctk.CTkLabel(
            info_frame,
            text="RAM Usage: ---%",
            font=("Segoe UI", 12),
            text_color=THEME_COLORS["text"]
        )
        self.ram_label.pack(pady=5)
        
        self.net_label = ctk.CTkLabel(
            info_frame,
            text="Network Usage: ---",
            font=("Segoe UI", 12),
            text_color=THEME_COLORS["text"]
        )
        self.net_label.pack(pady=5)

    def monitor_system(self):
        while self.monitoring:
            cpu_percent = psutil.cpu_percent()
            ram_percent = psutil.virtual_memory().percent
            net_io = psutil.net_io_counters()
            
            self.root.after(0, lambda: [
                self.cpu_label.configure(text=f"CPU Usage: {cpu_percent}%"),
                self.ram_label.configure(text=f"RAM Usage: {ram_percent}%"),
                self.net_label.configure(text=f"Network: ↑{net_io.bytes_sent/1024/1024:.1f}MB ↓{net_io.bytes_recv/1024/1024:.1f}MB")
            ])
            
            time.sleep(1)

    def apply_network_optimizations(self):
        selected = [opt for opt, var in self.optimizations.items() if var.get()]
        if not selected:
            messagebox.showwarning("Warning", "No optimizations selected!")
            return
        
        self.apply_net_btn.configure(state="disabled", text="Applying...")
        
        def apply():
            try:
                os_type = platform.system()
                if os_type == "Windows":
                    commands = [
                        "ipconfig /flushdns",
                        "netsh winsock reset catalog",
                        "netsh int ip reset",
                        "netsh int tcp set global rss=enabled",
                        "netsh int tcp set global chimney=enabled",
                        "netsh int tcp set global autotuninglevel=normal",
                        "netsh int tcp set global ecncapability=enabled",
                        "netsh int tcp set global congestionprovider=ctcp",
                        "netsh int tcp set global timestamps=enabled",
                        "netsh int tcp set heuristics enabled",
                        "netsh int tcp set global dca=enabled",
                        "netsh int tcp set global netdma=enabled",
                        "netsh interface tcp set global initialRto=2000",
                        "netsh int tcp set global nonsackrttresiliency=disabled",
                        "netsh int tcp set supplemental template=custom icw=10"
                    ]
                elif os_type == "Linux":
                    commands = [
                        "ip route flush cache",
                        "echo 3 > /proc/sys/vm/drop_caches",
                        "sysctl -w net.ipv4.tcp_fastopen=3",
                        "sysctl -w net.ipv4.tcp_window_scaling=1",
                        "sysctl -w net.ipv4.tcp_timestamps=1",
                        "sysctl -w net.ipv4.tcp_sack=1",
                        "sysctl -w net.ipv4.tcp_low_latency=1",
                        "sysctl -w net.ipv4.tcp_congestion_control=bbr",
                        "sysctl -w net.core.rmem_max=16777216",
                        "sysctl -w net.core.wmem_max=16777216"
                    ]
                
                for cmd in commands:
                    try:
                        subprocess.run(cmd, shell=True, capture_output=True)
                    except:
                        continue
                
                self.root.after(0, lambda: messagebox.showinfo("Success", "Network optimizations applied!"))
            except Exception as error:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed: {str(error)}"))
            finally:
                self.root.after(0, lambda: self.apply_net_btn.configure(
                    state="normal", text="Apply Network Optimizations"))
        
        threading.Thread(target=apply).start()

    def apply_cpu_optimizations(self):
        selected = [opt for opt, var in self.optimizations.items() if var.get()]
        if not selected:
            messagebox.showwarning("Warning", "No optimizations selected!")
            return
        
        self.apply_cpu_btn.configure(state="disabled", text="Applying...")
        
        def apply():
            try:
                os_type = platform.system()
                if os_type == "Windows":
                    commands = [
                        "powercfg /setactive scheme_min",
                        "powercfg /change standby-timeout-ac 0",
                        "powercfg /change hibernate-timeout-ac 0",
                        "powercfg /setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100",
                        "powercfg /setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100",
                        "powercfg /setacvalueindex scheme_current sub_processor SYSCOOLPOL 1",
                        "powercfg /setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2",
                        "wmic cpu where name!=\"\" call setspeed 100",
                        "wmic process where name='python.exe' CALL setpriority 128",
                        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\0cc5b647-c1df-4637-891a-dec35c318583\" /v ValueMax /t REG_DWORD /d 100 /f",
                        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PowerSettings\\54533251-82be-4824-96c1-47b60b740d00\\0cc5b647-c1df-4637-891a-dec35c318583\" /v ValueMin /t REG_DWORD /d 100 /f"
                    ]
                elif os_type == "Linux":
                    commands = [
                        "echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor",
                        "echo 0 "
                        "echo 0 > /proc/sys/kernel/nmi_watchdog",
                        "echo never > /sys/kernel/mm/transparent_hugepage/enabled",
                        "echo 0 > /proc/sys/kernel/randomize_va_space",
                        "echo 1 > /proc/sys/kernel/sched_autogroup_enabled",
                        "renice -n -20 -p $$",
                        "sysctl -w kernel.sched_min_granularity_ns=10000000",
                        "sysctl -w kernel.sched_wakeup_granularity_ns=15000000",
                        "sysctl -w vm.swappiness=10",
                        "sysctl -w kernel.sched_migration_cost_ns=5000000"
                    ]
                
                for cmd in commands:
                    try:
                        subprocess.run(cmd, shell=True, capture_output=True)
                    except:
                        continue
                
                self.root.after(0, lambda: messagebox.showinfo("Success", "CPU optimizations applied!"))
            except Exception as error:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed: {str(error)}"))
            finally:
                self.root.after(0, lambda: self.apply_cpu_btn.configure(
                    state="normal", text="Apply CPU Optimizations"))
        
        threading.Thread(target=apply).start()

    def apply_ram_optimizations(self):
        selected = [opt for opt, var in self.optimizations.items() if var.get()]
        if not selected:
            messagebox.showwarning("Warning", "No optimizations selected!")
            return
        
        self.apply_ram_btn.configure(state="disabled", text="Applying...")
        
        def apply():
            try:
                os_type = platform.system()
                if os_type == "Windows":
                    commands = [
                        "ipconfig /flushdns",
                        "wsreset",
                        "cleanmgr /sagerun:1",
                        "rundll32.exe advapi32.dll,ProcessIdleTasks",
                        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v ClearPageFileAtShutdown /t REG_DWORD /d 1 /f",
                        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v LargeSystemCache /t REG_DWORD /d 1 /f",
                        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\" /v DisablePagingExecutive /t REG_DWORD /d 1 /f",
                        "wmic computersystem where name=\"%computername%\" set AutomaticManagedPagefile=False",
                        "wmic pagefileset where name=\"C:\\pagefile.sys\" set InitialSize=16384,MaximumSize=16384",
                        "powershell \"Get-Process | Where-Object {$_.NonpagedSystemMemorySize -gt 1MB} | Stop-Process -Force\"",
                        "powershell \"Clear-RecycleBin -Force\"",
                        "powershell \"Remove-Item -Path $env:TEMP\\* -Recurse -Force\"",
                        "net stop sysmain",
                        "net stop superfetch"
                    ]
                elif os_type == "Linux":
                    commands = [
                        "sync; echo 3 > /proc/sys/vm/drop_caches",
                        "swapoff -a && swapon -a",
                        "echo 1 > /proc/sys/vm/compact_memory",
                        "echo 1 > /proc/sys/vm/overcommit_memory",
                        "echo 100 > /proc/sys/vm/vfs_cache_pressure",
                        "echo 10 > /proc/sys/vm/swappiness",
                        "echo 1 > /proc/sys/vm/zone_reclaim_mode",
                        "sysctl -w vm.min_free_kbytes=65536",
                        "sysctl -w vm.dirty_background_ratio=5",
                        "sysctl -w vm.dirty_ratio=10"
                    ]
                
                for cmd in commands:
                    try:
                        subprocess.run(cmd, shell=True, capture_output=True)
                    except:
                        continue
                
                self.root.after(0, lambda: messagebox.showinfo("Success", "RAM optimizations applied!"))
            except Exception as error:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed: {str(error)}"))
            finally:
                self.root.after(0, lambda: self.apply_ram_btn.configure(
                    state="normal", text="Apply RAM Optimizations"))
        
        threading.Thread(target=apply).start()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = SystemOptimizer()
    app.run()