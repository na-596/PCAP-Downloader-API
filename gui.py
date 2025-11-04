import customtkinter as ctk
import threading
import queue
import sys
import io
import os
from datetime import datetime
from main_script import run_pcap_process
from sctp_search_athena import filter_sctp_diameter
from query_options import get_time_window


"""Simple GUI wrapper for running PCAP downloads and analysis.

This module provides a small Tkinter-based interface used in the publish
package. It redirects stdout into the UI text widget, offers presets for
common time windows, and invokes the search/merge helpers on a background
thread so the UI remains responsive.
"""

class StreamRedirect(io.StringIO):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue
        self.buffer = ""

    def write(self, msg):
        self.buffer += msg
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)
            if line.strip():
                self.queue.put(line + '\n')

    def flush(self):
        if self.buffer.strip():
            self.queue.put(self.buffer)
            self.buffer = ""

class PCAPDownloaderGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PCAP Downloader and Analyser")
        self.geometry("900x700")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Configure grid weights
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)  # Main content area
        self.grid_rowconfigure(1, weight=0)  # Status bar

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Main container
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(0, weight=0)  # Input section (fixed height)
        self.main_frame.grid_rowconfigure(1, weight=0)  # Button section (fixed height)
        self.main_frame.grid_rowconfigure(2, weight=1)  # Output section (expandable)

        # Input section
        self.input_frame = ctk.CTkFrame(self.main_frame)
        self.input_frame.grid(row=0, column=0, padx=20, pady=10, sticky="ew")
        self.input_frame.grid_columnconfigure(1, weight=1)

        # ICCID input
        self.iccid_entry = self.create_labeled_entry(self.input_frame, "ICCID:", "8944538523026980428", 0)

        # Start time input
        self.start_entry = self.create_labeled_entry(self.input_frame, "Start Time:", "2025/08/18 11:50:00", 1)

        # End time input
        #self.end_entry = self.create_labeled_entry(self.input_frame, "End Time:", datetime.today().strftime("%Y/%m/%d %H:%M:%S"), 2)
        self.end_entry = self.create_labeled_entry(self.input_frame, "End Time:", "2025/08/18 12:52:00", 2)

        # Time window presets
        self.preset_label = ctk.CTkLabel(self.input_frame, text="Time Preset:", font=ctk.CTkFont(size=13, weight="bold"))
        self.preset_label.grid(row=3, column=0, padx=(15, 8), pady=6, sticky="w")
        
        self.preset_var = ctk.StringVar(value="Custom")
        self.preset_combo = ctk.CTkComboBox(
            self.input_frame,
            values=["Custom", "Last 30 Minutes", "Last Hour", "Last 6 Hours", "Last 24 Hours", "Last 48 Hours", "Last 72 Hours", "Last Week", "Last 2 Weeks", "Last Month", "Last 2 Months", "Last 6 Months", "Last Year", "All Time"],
            variable=self.preset_var,
            command=self.on_preset_change,
            width=300,
            height=28,
            state="readonly",
            border_width=1
        )
        self.preset_combo.grid(row=3, column=1, padx=(0, 15), pady=6, sticky="ew")
        
        # Bind click to time preset box
        self.preset_combo.bind("<Button-1>", lambda e: self.preset_combo._open_dropdown_menu())

        # Search type selection
        self.search_type_label = ctk.CTkLabel(self.input_frame, text="Search type:", font=ctk.CTkFont(size=13, weight="bold"))
        self.search_type_label.grid(row=4, column=0, padx=(15, 8), pady=6, sticky="w")
        self.search_type_var = ctk.StringVar(value="SCTP")
        self.search_type_segmented = ctk.CTkSegmentedButton(
            self.input_frame,
            values=["Radius", "No Radius", "SCTP"],
            variable=self.search_type_var,
            width=300,
            height=28,
        )
        self.search_type_segmented.grid(row=4, column=1, padx=(0, 15), pady=6, sticky="ew")

        # Max process size input
        self.max_process_size_entry = self.create_labeled_entry(self.input_frame, "Max Process Size (MB):", "2000", 5)

        # Button section
        self.button_frame = ctk.CTkFrame(self.main_frame)
        self.button_frame.grid(row=1, column=0, pady=10)

        self.run_button = ctk.CTkButton(
            self.button_frame, 
            text="Run", 
            command=self.start_thread,
            font=ctk.CTkFont(size=12, weight="bold"),
            height=30,
            fg_color="#2E8B57",
            hover_color="#228B22"
        )
        self.run_button.pack(side="left", padx=10)

        self.bind('<Return>', lambda event: self.start_thread())

        self.clear_button = ctk.CTkButton(
            self.button_frame, 
            text="Clear", 
            command=self.clear_output,
            font=ctk.CTkFont(size=12, weight="bold"),
            height=30,
            fg_color="#DAA520",
            hover_color="#B8860B"
        )
        self.clear_button.pack(side="left", padx=10)

        # Output text
        self.output_text = ctk.CTkTextbox(
            self.main_frame, 
            height=300, 
            wrap="word",
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.output_text.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.output_text.configure(state="disabled")

        # Status bar at the bottom of the window
        self.status_bar = ctk.CTkFrame(self, height=30)
        self.status_bar.grid(row=1, column=0, sticky="ew", padx=0, pady=0)
        self.status_bar.grid_columnconfigure(0, weight=1)
        self.status_bar.grid_columnconfigure(1, weight=0)
        
        self.status_label = ctk.CTkLabel(
            self.status_bar, 
            text="Ready", 
            font=ctk.CTkFont(size=12),
            anchor="w"
        )
        self.status_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.timestamp_label = ctk.CTkLabel(
            self.status_bar, 
            text="", 
            font=ctk.CTkFont(size=11),
            anchor="e"
        )
        self.timestamp_label.grid(row=0, column=1, padx=10, pady=5, sticky="e")

        self.log_queue = queue.Queue()
        self.stdout_redirect = StreamRedirect(self.log_queue)
        self.check_queue()

    def create_labeled_entry(self, parent, label_text, default_value, row, font_size=13, width=300, height=28):
        label = ctk.CTkLabel(parent, text=label_text, font=ctk.CTkFont(size=font_size, weight="bold"))
        label.grid(row=row, column=0, padx=(15, 8), pady=6, sticky="w")
        entry = ctk.CTkEntry(parent, width=width, height=height)
        entry.insert(0, default_value)
        entry.grid(row=row, column=1, padx=(0, 15), pady=6, sticky="ew")
        return entry

    def on_preset_change(self, choice):
        """Handle preset time window selection"""
        if choice == "Custom":
            return
        
        preset_map = {
            "Last 30 Minutes": "last_half_hour",
            "Last Hour": "last_hour",
            "Last 6 Hours": "last_6_hours",
            "Last 24 Hours": "last_24_hours",
            "Last 48 Hours": "last_48_hours",
            "Last 72 Hours": "last_72_hours",
            "Last Week": "last_week",
            "Last 2 Weeks": "last_2_weeks",
            "Last Month": "last_month",
            "Last 2 Months": "last_2_months",
            "Last 6 Months": "last_6_months",
            "Last Year": "last_year",
            "All Time": "all_time"
        }
        
        try:
            start_time, end_time = get_time_window(preset_map[choice])
            self.start_entry.delete(0, "end")
            self.start_entry.insert(0, start_time)
            self.end_entry.delete(0, "end")
            self.end_entry.insert(0, end_time)
        except Exception as e:
            print(f"Error setting time window: {e}")

    def format_message(self, msg):
        """Format messages with colours and better styling"""
        if not msg.strip():
            return msg
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if "error" in msg.lower():
            return f"[{timestamp}] ❌ {msg}"
        else:
            return f"[{timestamp}] {msg}"

    def clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")

    def start_thread(self):
        self.status_label.configure(text="Running...")
        self.timestamp_label.configure(text=f"Started: {datetime.now().strftime('%H:%M:%S')}")
        self.output_text.configure(state="normal")
        self.run_button.configure(state="disabled")
        threading.Thread(target=self.run_process, daemon=True).start()

    def run_process(self):
        # Redirect stdout into the UI's queue so printed progress appears in the textbox
        sys.stdout = self.stdout_redirect
        try:
            # Basic input validation: ensure required fields are populated
            if any(not entry.get().strip() for entry in [self.iccid_entry, self.start_entry, self.end_entry, self.max_process_size_entry]):
                print("Error: All input fields must be filled out.")
                self.status_label.configure(text="Error: All input fields must be filled out.")
                return

            selected_search = self.search_type_var.get()
            if selected_search == "SCTP":
                # Call the SCTP-focused helper which will perform Athena -> CSV -> PCAP -> filter
                max_bytes = int(self.max_process_size_entry.get()) * 1024 * 1024
                print("Running SCTP search...")
                print(f"Time window: {self.start_entry.get()} to {self.end_entry.get()}")
                filter_sctp_diameter(
                    self.iccid_entry.get(),
                    self.start_entry.get(),
                    self.end_entry.get(),
                    max_bytes,
                )
                self.status_label.configure(text="Completed (SCTP)")
                return

            # Otherwise call the more general run_pcap_process which may include Radius handling
            radius_flag = True if selected_search == "Radius" else False
            run_pcap_process(
                self.iccid_entry.get(),
                self.start_entry.get(),
                self.end_entry.get(),
                int(self.max_process_size_entry.get()) * 1024 * 1024,
                radius_flag,
            )
            self.status_label.configure(text="Completed")
        except Exception as e:
            # Surface exceptions in the UI for debugging
            print(f"Error: {e}")
            self.status_label.configure(text="Failed")
        finally:
            # Always restore stdout and re-enable the run button
            sys.stdout = sys.__stdout__
            self.run_button.configure(state="normal")

    def check_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                formatted_msg = self.format_message(msg)
                self.output_text.configure(state="normal")
                self.output_text.insert("end", formatted_msg)
                self.output_text.see("end")
                self.output_text.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self.check_queue)

    def on_close(self):
        self.destroy()
        os._exit(0)

if __name__ == "__main__":
    app = PCAPDownloaderGUI()
    app.mainloop()
