import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import csv
import os

class PacketCaptureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Traffic Analyzer")
        
        # 设置窗口大小为原来的8倍
        self.root.geometry("1960x1080")
        
        # 设置GUI组件
        self.capture_button = tk.Button(root, text="Start Capture", command=self.start_capture)
        self.capture_button.pack(pady=10)
        
        self.stop_button = tk.Button(root, text="Stop Capture", state=tk.DISABLED, command=self.stop_capture)
        self.stop_button.pack(pady=10)
        
        self.output_text = tk.Text(root, height=200, width=600)  # 增大文本框
        self.output_text.pack(pady=10)
        
        # 创建进度条
        self.progress_label = tk.Label(root, text="Exporting report...")
        self.progress_label.pack(pady=10)
        
        self.progress_bar = ttk.Progressbar(root, length=600, mode="determinate")
        self.progress_bar.pack(pady=10)
        
        self.capture_thread = None
        self.sniffing = False
        self.packets = []  # 存储捕获的包
        self.export_report_in_progress = False  # 控制导出报告状态
        
    def start_capture(self):
        # 启动数据包捕获线程
        self.sniffing = True
        self.packets.clear()  # 清空之前捕获的包
        self.capture_thread = threading.Thread(target=self.sniff_packets)
        self.capture_thread.daemon = True  # 设置为守护线程，这样在程序退出时可以自动退出
        self.capture_thread.start()
        
        self.capture_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
    
    def stop_capture(self):
        # 停止数据包捕获
        self.sniffing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)  # 等待线程结束，最多等待5秒
        
        # 启动导出报告并显示进度条
        self.export_report_in_progress = True
        self.save_report()  # 开始保存报告
        
        # 显示导出成功弹窗
        messagebox.showinfo("Export Successful", "Traffic report has been successfully exported.")
        
        # 重新回到主窗口
        self.capture_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
   

    def sniff_packets(self):
        # 过滤条件：可以根据需求修改
        filter_condition = "ip"  # 过滤IPv4包
        
        # 使用Scapy的sniff函数捕获数据包
        sniff(prn=self.process_packet, store=0, filter=filter_condition, stop_filter=self.stop_sniffing)

    def stop_sniffing(self, packet):
        # 停止抓包的条件（例如捕获指定数量的包）
        if not self.sniffing:
            return True
        return False
    
    def process_packet(self, packet):
        # 处理捕获的数据包
        self.output_text.insert(tk.END, f"Packet Captured: {packet.summary()}\n")
        self.output_text.yview(tk.END)  # 自动滚动到底部

        # 解析和显示包的主要字段
        if IP in packet:
            ip_packet = packet[IP]
            source_ip = ip_packet.src
            dest_ip = ip_packet.dst
            protocol = ip_packet.proto
            self.output_text.insert(tk.END, f"IP Packet: {source_ip} -> {dest_ip}, Protocol: {protocol}\n")
            
            # 根据协议类型细分
            if protocol == 6:  # TCP
                if TCP in packet:
                    self.output_text.insert(tk.END, f"TCP Segment: {packet[TCP].summary()}\n")
            elif protocol == 17:  # UDP
                if UDP in packet:
                    self.output_text.insert(tk.END, f"UDP Segment: {packet[UDP].summary()}\n")
            elif protocol == 1:  # ICMP
                if ICMP in packet:
                    self.output_text.insert(tk.END, f"ICMP Packet: {packet[ICMP].summary()}\n")
            
            self.output_text.insert(tk.END, "-"*50 + "\n")
            
            # 将捕获的包存储在self.packets列表中
            self.packets.append({
                "Source IP": ip_packet.src,
                "Destination IP": ip_packet.dst,
                "Protocol": protocol,
                "Summary": packet.summary()
            })

    def save_report(self):
        # 导出捕获的流量数据到CSV文件
        if not self.packets:
            return
        
        file_path = os.path.join(os.getcwd(), "traffic_report.csv")
        
        # 设置进度条最大值
        self.progress_bar.config(maximum=len(self.packets))
        self.progress_bar.start()

        with open(file_path, "w", newline="") as csvfile:
            fieldnames = ["Source IP", "Destination IP", "Protocol", "Summary"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # 遍历包并写入CSV文件，同时更新进度条
            for index, packet in enumerate(self.packets):
                writer.writerow(packet)
                # 更新进度条
                self.progress_bar["value"] = index + 1
                self.root.update_idletasks()  # 刷新窗口

        self.progress_bar.stop()  # 停止进度条
        self.output_text.insert(tk.END, f"\nTraffic report saved to {file_path}\n")
        self.output_text.yview(tk.END)  # 自动滚动到底部

# 创建并运行GUI应用
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketCaptureApp(root)
    root.mainloop()

