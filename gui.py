import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
import os
import glob

from analyze_pcap3 import analyze_pcap


class TraceNF_GUI:

    def __init__(self, root):
        self.root = root
        self.root.title("TRACE-NF | Network Forensics Dashboard")
        self.root.geometry("1000x650")
        self.root.configure(bg="#0f172a")

        self.file_path = ""
        self.latest_pdf = None

        self.build_ui()

    # -----------------------------
    # UI Layout
    # -----------------------------
    def build_ui(self):

        # HEADER
        header = tk.Label(
            self.root,
            text="TRACE-NF",
            font=("Segoe UI", 28, "bold"),
            fg="white",
            bg="#0f172a"
        )
        header.pack(pady=10)

        subtitle = tk.Label(
            self.root,
            text="Timeline-Based Network Forensics & Attack Detection",
            font=("Segoe UI", 12),
            fg="#94a3b8",
            bg="#0f172a"
        )
        subtitle.pack()

        # MAIN CONTAINER
        container = tk.Frame(self.root, bg="#0f172a")
        container.pack(fill="both", expand=True, padx=20, pady=20)

        # LEFT PANEL
        left_panel = tk.Frame(container, bg="#1e293b")
        left_panel.pack(side="left", fill="y", padx=10, pady=10)

        # Upload Button
        upload_btn = tk.Button(
            left_panel,
            text="📂 Upload PCAP",
            command=self.upload_file,
            font=("Segoe UI", 12, "bold"),
            bg="#2563eb",
            fg="white",
            width=20,
            height=2,
            bd=0
        )
        upload_btn.pack(pady=20)

        # File Label
        self.file_label = tk.Label(
            left_panel,
            text="No file selected",
            wraplength=200,
            fg="#cbd5f5",
            bg="#1e293b"
        )
        self.file_label.pack(pady=10)

        # Run Button
        run_btn = tk.Button(
            left_panel,
            text="🚀 Run Analysis",
            command=self.run_analysis,
            font=("Segoe UI", 12, "bold"),
            bg="#16a34a",
            fg="white",
            width=20,
            height=2,
            bd=0
        )
        run_btn.pack(pady=10)

        # Open PDF Button
        open_btn = tk.Button(
            left_panel,
            text="📄 Open Report",
            command=self.open_pdf,
            font=("Segoe UI", 11),
            bg="#7c3aed",
            fg="white",
            width=20,
            height=2,
            bd=0
        )
        open_btn.pack(pady=10)

        # Status
        self.status_label = tk.Label(
            left_panel,
            text="Status: Idle",
            fg="#facc15",
            bg="#1e293b",
            font=("Segoe UI", 10)
        )
        self.status_label.pack(pady=20)

        # RIGHT PANEL
        right_panel = tk.Frame(container, bg="#020617")
        right_panel.pack(side="right", fill="both", expand=True)

        # Title
        report_title = tk.Label(
            right_panel,
            text="📊 Forensic Report",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg="#020617"
        )
        report_title.pack(pady=10)

        # Output Box
        self.output_box = scrolledtext.ScrolledText(
            right_panel,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#020617",
            fg="#e2e8f0",
            insertbackground="white"
        )
        self.output_box.pack(fill="both", expand=True, padx=10, pady=10)

    # -----------------------------
    # Upload File
    # -----------------------------
    def upload_file(self):

        file_path = filedialog.askopenfilename(
            filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")]
        )

        if file_path:
            self.file_path = file_path
            self.file_label.config(text=os.path.basename(file_path))

    # -----------------------------
    # Run Analysis
    # -----------------------------
    def run_analysis(self):

        if not self.file_path:
            messagebox.showerror("Error", "Please upload a PCAP file first.")
            return

        self.output_box.delete(1.0, tk.END)
        self.status_label.config(text="Status: Running Analysis...")

        thread = threading.Thread(target=self.run_backend)
        thread.start()

    # -----------------------------
    # Backend Execution
    # -----------------------------
    def run_backend(self):

        try:
            import sys
            from io import StringIO
            import asyncio

            # ✅ FIX: Create event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            old_stdout = sys.stdout
            sys.stdout = buffer = StringIO()

            # Run your backend
            analyze_pcap(self.file_path)

            sys.stdout = old_stdout

            result = buffer.getvalue()

            self.output_box.insert(tk.END, result)

            # Get latest PDF
            import glob
            pdf_files = glob.glob("output/*.pdf")
            if pdf_files:
                self.latest_pdf = max(pdf_files, key=os.path.getctime)

            self.status_label.config(text="Status: Completed ✅")

            if self.latest_pdf:
                messagebox.showinfo(
                    "Success",
                    f"Report generated successfully!\n\nSaved at:\n{self.latest_pdf}"
                )

        except Exception as e:
            self.status_label.config(text="Status: Error ❌")
            messagebox.showerror("Error", str(e))

    # -----------------------------
    # Open PDF
    # -----------------------------
    def open_pdf(self):

        if self.latest_pdf and os.path.exists(self.latest_pdf):
            os.startfile(self.latest_pdf)
        else:
            messagebox.showwarning("Warning", "No report available yet.")


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = TraceNF_GUI(root)
    root.mainloop()