import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import socket
import struct
import json
import os
from datetime import datetime
from collections import defaultdict

class FirewallRule:
    def __init__(self, name, action, protocol, src_ip, src_port, dst_ip, dst_port, direction):
        self.name = name
        self.action = action  # ALLOW or BLOCK
        self.protocol = protocol  # TCP, UDP, ICMP, ALL
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.direction = direction  # INBOUND, OUTBOUND, BOTH
        self.enabled = True
        self.hit_count = 0

    def matches(self, packet_info):
        if not self.enabled:
            return False
        
        # Check protocol
        if self.protocol != "ALL" and packet_info['protocol'] != self.protocol:
            return False
        
        # Check direction
        if self.direction == "INBOUND" and packet_info['direction'] != "INBOUND":
            return False
        if self.direction == "OUTBOUND" and packet_info['direction'] != "OUTBOUND":
            return False
        
        # Check IPs
        if self.src_ip != "ANY" and packet_info['src_ip'] != self.src_ip:
            if not self._ip_in_range(packet_info['src_ip'], self.src_ip):
                return False
        
        if self.dst_ip != "ANY" and packet_info['dst_ip'] != self.dst_ip:
            if not self._ip_in_range(packet_info['dst_ip'], self.dst_ip):
                return False
        
        # Check ports
        if self.src_port != "ANY" and str(packet_info['src_port']) != str(self.src_port):
            return False
        
        if self.dst_port != "ANY" and str(packet_info['dst_port']) != str(self.dst_port):
            return False
        
        return True
    
    def _ip_in_range(self, ip, range_pattern):
        # Simple wildcard matching (e.g., 192.168.1.*)
        if '*' in range_pattern:
            pattern_parts = range_pattern.split('.')
            ip_parts = ip.split('.')
            for p, i in zip(pattern_parts, ip_parts):
                if p != '*' and p != i:
                    return False
            return True
        return False

    def to_dict(self):
        return {
            'name': self.name,
            'action': self.action,
            'protocol': self.protocol,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'direction': self.direction,
            'enabled': self.enabled
        }

class FirewallEngine:
    def __init__(self):
        self.rules = []
        self.running = False
        self.log_callback = None
        self.stats = defaultdict(int)
        self.default_policy = "ALLOW"  # ALLOW or BLOCK
        
    def add_rule(self, rule):
        self.rules.append(rule)
        
    def remove_rule(self, index):
        if 0 <= index < len(self.rules):
            self.rules.pop(index)
    
    def evaluate_packet(self, packet_info):
        # Check rules in order
        for rule in self.rules:
            if rule.matches(packet_info):
                rule.hit_count += 1
                action = rule.action
                self.log_packet(packet_info, action, rule.name)
                return action
        
        # Default policy if no rule matches
        self.log_packet(packet_info, self.default_policy, "Default Policy")
        return self.default_policy
    
    def log_packet(self, packet_info, action, rule_name):
        self.stats['total_packets'] += 1
        if action == "BLOCK":
            self.stats['blocked_packets'] += 1
        else:
            self.stats['allowed_packets'] += 1
        
        if self.log_callback:
            log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] {action} - {rule_name}\n"
            log_entry += f"  {packet_info['direction']} {packet_info['protocol']}: "
            log_entry += f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
            log_entry += f"{packet_info['dst_ip']}:{packet_info['dst_port']}\n"
            self.log_callback(log_entry)
    
    def save_rules(self, filename):
        with open(filename, 'w') as f:
            rules_data = [rule.to_dict() for rule in self.rules]
            json.dump(rules_data, f, indent=2)
    
    def load_rules(self, filename):
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                rules_data = json.load(f)
                self.rules = []
                for data in rules_data:
                    rule = FirewallRule(**data)
                    self.rules.append(rule)

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Firewall Prototype")
        self.root.geometry("1000x700")
        
        self.engine = FirewallEngine()
        self.engine.log_callback = self.add_log_entry
        
        # Load default rules
        self.load_default_rules()
        
        self.create_widgets()
        self.update_stats()
        
    def create_widgets(self):
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Rules", command=self.save_rules)
        file_menu.add_command(label="Load Rules", command=self.load_rules)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Firewall Control", padding="10")
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.status_label = ttk.Label(control_frame, text="Status: STOPPED", font=("Arial", 12, "bold"))
        self.status_label.grid(row=0, column=0, padx=5)
        
        self.start_btn = ttk.Button(control_frame, text="Start Firewall", command=self.start_firewall)
        self.start_btn.grid(row=0, column=1, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Firewall", command=self.stop_firewall, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=2, padx=5)
        
        ttk.Label(control_frame, text="Default Policy:").grid(row=0, column=3, padx=5)
        self.policy_var = tk.StringVar(value="ALLOW")
        policy_combo = ttk.Combobox(control_frame, textvariable=self.policy_var, 
                                     values=["ALLOW", "BLOCK"], width=10, state="readonly")
        policy_combo.grid(row=0, column=4, padx=5)
        policy_combo.bind("<<ComboboxSelected>>", self.change_default_policy)
        
        # Stats panel
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="10")
        stats_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.stats_label = ttk.Label(stats_frame, text="Total: 0 | Allowed: 0 | Blocked: 0")
        self.stats_label.pack()
        
        # Rules panel
        rules_frame = ttk.LabelFrame(main_frame, text="Firewall Rules", padding="10")
        rules_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        
        # Rules treeview
        columns = ("Name", "Action", "Protocol", "Source", "Destination", "Direction", "Hits")
        self.rules_tree = ttk.Treeview(rules_frame, columns=columns, show="tree headings", height=10)
        
        self.rules_tree.column("#0", width=30)
        self.rules_tree.heading("#0", text="✓")
        
        for col in columns:
            self.rules_tree.heading(col, text=col)
            if col == "Name":
                self.rules_tree.column(col, width=150)
            elif col in ["Action", "Protocol", "Direction"]:
                self.rules_tree.column(col, width=80)
            else:
                self.rules_tree.column(col, width=100)
        
        self.rules_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        rules_scrollbar = ttk.Scrollbar(rules_frame, orient=tk.VERTICAL, command=self.rules_tree.yview)
        rules_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.rules_tree.configure(yscrollcommand=rules_scrollbar.set)
        
        # Rule buttons
        rule_btn_frame = ttk.Frame(rules_frame)
        rule_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(rule_btn_frame, text="Add Rule", command=self.add_rule_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(rule_btn_frame, text="Remove Rule", command=self.remove_rule).pack(side=tk.LEFT, padx=2)
        ttk.Button(rule_btn_frame, text="Toggle Enable", command=self.toggle_rule).pack(side=tk.LEFT, padx=2)
        ttk.Button(rule_btn_frame, text="Refresh", command=self.refresh_rules).pack(side=tk.LEFT, padx=2)
        
        # Log panel
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10")
        log_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, width=50, height=20, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        log_btn_frame = ttk.Frame(log_frame)
        log_btn_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(log_btn_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=2)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        self.refresh_rules()
    
    def load_default_rules(self):
        # Add some default rules
        self.engine.add_rule(FirewallRule("Block Malicious IPs", "BLOCK", "ALL", "192.168.1.100", "ANY", "ANY", "ANY", "BOTH"))
        self.engine.add_rule(FirewallRule("Allow HTTP", "ALLOW", "TCP", "ANY", "ANY", "ANY", "80", "OUTBOUND"))
        self.engine.add_rule(FirewallRule("Allow HTTPS", "ALLOW", "TCP", "ANY", "ANY", "ANY", "443", "OUTBOUND"))
        self.engine.add_rule(FirewallRule("Allow DNS", "ALLOW", "UDP", "ANY", "ANY", "ANY", "53", "OUTBOUND"))
        self.engine.add_rule(FirewallRule("Block Telnet", "BLOCK", "TCP", "ANY", "ANY", "ANY", "23", "BOTH"))
    
    def start_firewall(self):
        self.engine.running = True
        self.status_label.config(text="Status: RUNNING", foreground="green")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.add_log_entry("=== Firewall Started ===\n")
        
        # Start simulation thread
        self.simulation_thread = threading.Thread(target=self.simulate_traffic, daemon=True)
        self.simulation_thread.start()
    
    def stop_firewall(self):
        self.engine.running = False
        self.status_label.config(text="Status: STOPPED", foreground="red")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.add_log_entry("=== Firewall Stopped ===\n")
    
    def simulate_traffic(self):
        import random
        import time
        
        protocols = ["TCP", "UDP", "ICMP"]
        ips = ["192.168.1.100", "192.168.1.50", "8.8.8.8", "1.1.1.1", "10.0.0.5"]
        ports = [80, 443, 53, 23, 8080, 3389, 22]
        directions = ["INBOUND", "OUTBOUND"]
        
        while self.engine.running:
            packet_info = {
                'protocol': random.choice(protocols),
                'src_ip': random.choice(ips),
                'src_port': random.choice(ports),
                'dst_ip': random.choice(ips),
                'dst_port': random.choice(ports),
                'direction': random.choice(directions)
            }
            
            self.engine.evaluate_packet(packet_info)
            time.sleep(random.uniform(0.5, 2.0))
    
    def add_rule_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Firewall Rule")
        dialog.geometry("400x400")
        
        frame = ttk.Frame(dialog, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Rule fields
        ttk.Label(frame, text="Rule Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        name_entry = ttk.Entry(frame, width=30)
        name_entry.grid(row=0, column=1, pady=5)
        
        ttk.Label(frame, text="Action:").grid(row=1, column=0, sticky=tk.W, pady=5)
        action_var = tk.StringVar(value="BLOCK")
        action_combo = ttk.Combobox(frame, textvariable=action_var, values=["ALLOW", "BLOCK"], width=28, state="readonly")
        action_combo.grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="Protocol:").grid(row=2, column=0, sticky=tk.W, pady=5)
        protocol_var = tk.StringVar(value="TCP")
        protocol_combo = ttk.Combobox(frame, textvariable=protocol_var, values=["ALL", "TCP", "UDP", "ICMP"], width=28, state="readonly")
        protocol_combo.grid(row=2, column=1, pady=5)
        
        ttk.Label(frame, text="Source IP:").grid(row=3, column=0, sticky=tk.W, pady=5)
        src_ip_entry = ttk.Entry(frame, width=30)
        src_ip_entry.insert(0, "ANY")
        src_ip_entry.grid(row=3, column=1, pady=5)
        
        ttk.Label(frame, text="Source Port:").grid(row=4, column=0, sticky=tk.W, pady=5)
        src_port_entry = ttk.Entry(frame, width=30)
        src_port_entry.insert(0, "ANY")
        src_port_entry.grid(row=4, column=1, pady=5)
        
        ttk.Label(frame, text="Destination IP:").grid(row=5, column=0, sticky=tk.W, pady=5)
        dst_ip_entry = ttk.Entry(frame, width=30)
        dst_ip_entry.insert(0, "ANY")
        dst_ip_entry.grid(row=5, column=1, pady=5)
        
        ttk.Label(frame, text="Destination Port:").grid(row=6, column=0, sticky=tk.W, pady=5)
        dst_port_entry = ttk.Entry(frame, width=30)
        dst_port_entry.insert(0, "ANY")
        dst_port_entry.grid(row=6, column=1, pady=5)
        
        ttk.Label(frame, text="Direction:").grid(row=7, column=0, sticky=tk.W, pady=5)
        direction_var = tk.StringVar(value="BOTH")
        direction_combo = ttk.Combobox(frame, textvariable=direction_var, values=["INBOUND", "OUTBOUND", "BOTH"], width=28, state="readonly")
        direction_combo.grid(row=7, column=1, pady=5)
        
        def save_rule():
            name = name_entry.get()
            if not name:
                messagebox.showerror("Error", "Rule name is required")
                return
            
            rule = FirewallRule(
                name=name,
                action=action_var.get(),
                protocol=protocol_var.get(),
                src_ip=src_ip_entry.get(),
                src_port=src_port_entry.get(),
                dst_ip=dst_ip_entry.get(),
                dst_port=dst_port_entry.get(),
                direction=direction_var.get()
            )
            
            self.engine.add_rule(rule)
            self.refresh_rules()
            dialog.destroy()
        
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=8, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="Save", command=save_rule).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def remove_rule(self):
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to remove")
            return
        
        item = selection[0]
        index = self.rules_tree.index(item)
        
        if messagebox.askyesno("Confirm", "Are you sure you want to remove this rule?"):
            self.engine.remove_rule(index)
            self.refresh_rules()
    
    def toggle_rule(self):
        selection = self.rules_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a rule to toggle")
            return
        
        item = selection[0]
        index = self.rules_tree.index(item)
        self.engine.rules[index].enabled = not self.engine.rules[index].enabled
        self.refresh_rules()
    
    def refresh_rules(self):
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        
        for rule in self.engine.rules:
            check = "✓" if rule.enabled else "✗"
            src = f"{rule.src_ip}:{rule.src_port}"
            dst = f"{rule.dst_ip}:{rule.dst_port}"
            
            self.rules_tree.insert("", tk.END, text=check, values=(
                rule.name,
                rule.action,
                rule.protocol,
                src,
                dst,
                rule.direction,
                rule.hit_count
            ))
    
    def add_log_entry(self, message):
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        
        # Keep log size manageable
        if int(self.log_text.index('end-1c').split('.')[0]) > 1000:
            self.log_text.delete('1.0', '500.0')
    
    def clear_log(self):
        self.log_text.delete('1.0', tk.END)
    
    def update_stats(self):
        stats = self.engine.stats
        self.stats_label.config(
            text=f"Total: {stats['total_packets']} | "
                 f"Allowed: {stats['allowed_packets']} | "
                 f"Blocked: {stats['blocked_packets']}"
        )
        self.refresh_rules()
        self.root.after(1000, self.update_stats)
    
    def change_default_policy(self, event=None):
        self.engine.default_policy = self.policy_var.get()
        self.add_log_entry(f"Default policy changed to: {self.engine.default_policy}\n")
    
    def save_rules(self):
        self.engine.save_rules("firewall_rules.json")
        messagebox.showinfo("Success", "Rules saved successfully")
    
    def load_rules(self):
        self.engine.load_rules("firewall_rules.json")
        self.refresh_rules()
        messagebox.showinfo("Success", "Rules loaded successfully")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()
