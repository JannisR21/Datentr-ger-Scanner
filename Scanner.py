import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import psutil
import threading
from pathlib import Path
import shutil
import stat

class DiskAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Festplatten-Analyzer")
        self.root.geometry("1000x700")
        
        # Variablen
        self.file_data = []
        self.current_path = ""
        self.scanning = False
        
        # System-Schutz Variablen
        self.protect_system_files = True
        self.system_paths = self.get_system_paths()
        self.system_extensions = {
            '.sys', '.dll', '.exe', '.msi', '.cab', '.inf', '.cat', '.bat', '.cmd',
            '.vbs', '.ps1', '.reg', '.pol', '.adm', '.msc', '.cpl', '.scr', '.ocx',
            '.drv', '.mui', '.hlp', '.chm', '.edb', '.log', '.evt', '.evtx'
        }
        
        self.setup_ui()
        self.load_drives()
    
    def setup_ui(self):
        # Hauptframe
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Laufwerk-Auswahl
        drive_frame = ttk.LabelFrame(main_frame, text="Laufwerk auswählen", padding="5")
        drive_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(drive_frame, textvariable=self.drive_var, width=50)
        self.drive_combo.grid(row=0, column=0, padx=(0, 10))
        
        self.scan_button = ttk.Button(drive_frame, text="Scannen", command=self.start_scan)
        self.scan_button.grid(row=0, column=1)
        
        self.refresh_button = ttk.Button(drive_frame, text="Laufwerke aktualisieren", command=self.load_drives)
        self.refresh_button.grid(row=0, column=2, padx=(10, 0))
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Status Label
        self.status_var = tk.StringVar(value="Bereit zum Scannen")
        status_label = ttk.Label(main_frame, textvariable=self.status_var)
        status_label.grid(row=2, column=0, columnspan=2, pady=(0, 10))
        
        # Datei-Tabelle
        table_frame = ttk.LabelFrame(main_frame, text="Große Dateien", padding="5")
        table_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Treeview für Dateien
        columns = ("Dateiname", "Pfad", "Größe", "Größe (MB)")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=15)
        
        # Spalten konfigurieren mit Sortierfunktion
        self.tree.heading("Dateiname", text="Dateiname", command=lambda: self.sort_column("name", False))
        self.tree.heading("Pfad", text="Pfad", command=lambda: self.sort_column("path", False))
        self.tree.heading("Größe", text="Größe ↓", command=lambda: self.sort_column("size", True))
        self.tree.heading("Größe (MB)", text="Größe (MB)", command=lambda: self.sort_column("size_mb", True))
        
        self.tree.column("Dateiname", width=200)
        self.tree.column("Pfad", width=400)
        self.tree.column("Größe", width=100)
        self.tree.column("Größe (MB)", width=100)
        
        # Sortier-Variablen
        self.sort_column_name = "size"
        self.sort_reverse = True
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Rechtsklick-Kontextmenü
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Pfad kopieren", command=self.copy_path)
        self.context_menu.add_command(label="Dateiname kopieren", command=self.copy_filename)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Datei im Explorer öffnen", command=self.open_in_explorer)
        self.context_menu.add_command(label="Ordner im Explorer öffnen", command=self.open_folder_in_explorer)
        
        # Rechtsklick-Event binden
        self.tree.bind("<Button-3>", self.show_context_menu)  # Rechtsklick
        self.tree.bind("<Control-c>", self.copy_path)  # Strg+C für Pfad kopieren
        
        # Button-Frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=(10, 0))
        
        self.delete_button = ttk.Button(button_frame, text="Ausgewählte Dateien löschen", 
                                       command=self.delete_selected_files, state="disabled")
        self.delete_button.grid(row=0, column=0, padx=(0, 10))
        
        self.export_button = ttk.Button(button_frame, text="Liste exportieren", 
                                       command=self.export_list, state="disabled")
        self.export_button.grid(row=0, column=1, padx=(10, 0))
        
        # Filter-Frame
        filter_frame = ttk.LabelFrame(main_frame, text="Filter", padding="5")
        filter_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Label(filter_frame, text="Min. Größe (MB):").grid(row=0, column=0, padx=(0, 5))
        self.min_size_var = tk.StringVar(value="100")
        min_size_entry = ttk.Entry(filter_frame, textvariable=self.min_size_var, width=10)
        min_size_entry.grid(row=0, column=1, padx=(0, 20))
        
        ttk.Label(filter_frame, text="Dateierweiterung:").grid(row=0, column=2, padx=(0, 5))
        self.extension_var = tk.StringVar()
        extension_entry = ttk.Entry(filter_frame, textvariable=self.extension_var, width=10)
        extension_entry.grid(row=0, column=3, padx=(0, 20))
        
        filter_button = ttk.Button(filter_frame, text="Filter anwenden", command=self.apply_filter)
        filter_button.grid(row=0, column=4)
        
        clear_filter_button = ttk.Button(filter_frame, text="Filter zurücksetzen", command=self.clear_filter)
        clear_filter_button.grid(row=0, column=5, padx=(10, 0))
        
        # System-Schutz Checkbox
        system_frame = ttk.LabelFrame(main_frame, text="System-Schutz", padding="5")
        system_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.protect_system_var = tk.BooleanVar(value=True)
        protect_checkbox = ttk.Checkbutton(
            system_frame, 
            text="Systemwichtige Dateien schützen (empfohlen)", 
            variable=self.protect_system_var,
            command=self.toggle_system_protection
        )
        protect_checkbox.grid(row=0, column=0, sticky=tk.W)
        
        info_label = ttk.Label(
            system_frame, 
            text="Schützt Windows-Systemdateien, Programme und kritische Ordner vor versehentlichem Löschen",
            font=('TkDefaultFont', 8)
        )
        info_label.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        # Grid-Gewichte setzen
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
    
    def get_system_paths(self):
        """Gibt eine Liste der zu schützenden System-Pfade zurück"""
        system_paths = set()
        
        # Windows-Systemordner
        if os.name == 'nt':  # Windows
            # Umgebungsvariablen für Systempfade
            system_vars = ['WINDIR', 'SYSTEMROOT', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 
                          'PROGRAMDATA', 'ALLUSERSPROFILE']
            
            for var in system_vars:
                path = os.environ.get(var)
                if path and os.path.exists(path):
                    system_paths.add(path.lower())
            
            # Zusätzliche kritische Pfade
            additional_paths = [
                'C:\\Windows',
                'C:\\Program Files',
                'C:\\Program Files (x86)',
                'C:\\ProgramData',
                'C:\\System Volume Information',
                'C:\\$Recycle.Bin',
                'C:\\Recovery',
                'C:\\Boot',
                'C:\\EFI',
                'C:\\System32',
                'C:\\SysWOW64'
            ]
            
            for path in additional_paths:
                if os.path.exists(path):
                    system_paths.add(path.lower())
        
        return system_paths
    
    def is_system_file(self, file_path):
        """Prüft, ob eine Datei systemwichtig ist"""
        if not self.protect_system_files:
            return False
        
        file_path_lower = file_path.lower()
        
        # Prüfe Pfade
        for system_path in self.system_paths:
            if file_path_lower.startswith(system_path):
                return True
        
        # Prüfe Dateierweiterungen
        file_ext = Path(file_path).suffix.lower()
        if file_ext in self.system_extensions:
            return True
        
        # Prüfe versteckte/System-Attribute (Windows)
        try:
            if os.name == 'nt':
                attrs = os.stat(file_path).st_file_attributes
                # FILE_ATTRIBUTE_SYSTEM = 0x4, FILE_ATTRIBUTE_HIDDEN = 0x2
                if attrs & (0x4 | 0x2):
                    return True
        except (AttributeError, OSError):
            pass
        
        # Prüfe spezielle Dateinamen
        filename = os.path.basename(file_path_lower)
        system_files = {
            'ntldr', 'bootmgr', 'boot.ini', 'ntdetect.com', 'pagefile.sys', 
            'hiberfil.sys', 'swapfile.sys', 'bootfont.bin', 'bootsect.bak'
        }
        
        if filename in system_files:
            return True
        
        return False
    
    def toggle_system_protection(self):
        """Schaltet den System-Schutz ein/aus"""
        self.protect_system_files = self.protect_system_var.get()
        
        if self.protect_system_files:
            self.status_var.set("System-Schutz aktiviert - Systemdateien werden ausgeschlossen")
        else:
            self.status_var.set("⚠️ WARNUNG: System-Schutz deaktiviert - Alle Dateien werden angezeigt!")
            messagebox.showwarning(
                "System-Schutz deaktiviert", 
                "WARNUNG: Der System-Schutz wurde deaktiviert!\n\n"
                "Das Programm zeigt jetzt auch systemwichtige Dateien an.\n"
                "Das Löschen dieser Dateien kann Windows beschädigen!\n\n"
                "Aktivieren Sie den Schutz wieder, um sicher zu bleiben."
            )
    
    def load_drives(self):
        """Lädt verfügbare Laufwerke"""
        drives = []
        partitions = psutil.disk_partitions()
        
        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                drive_info = f"{partition.device} - {partition.fstype} - "
                drive_info += f"Gesamt: {self.format_bytes(usage.total)} - "
                drive_info += f"Frei: {self.format_bytes(usage.free)}"
                drives.append(drive_info)
            except Exception:
                continue
        
        self.drive_combo['values'] = drives
        if drives:
            self.drive_combo.current(0)
    
    def format_bytes(self, bytes_size):
        """Formatiert Bytes in lesbare Einheiten"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"
    
    def start_scan(self):
        """Startet den Scan-Prozess in einem separaten Thread"""
        if self.scanning:
            return
        
        selected_drive = self.drive_var.get()
        if not selected_drive:
            messagebox.showerror("Fehler", "Bitte wählen Sie ein Laufwerk aus!")
            return
        
        # Extrahiere Laufwerksbuchstaben
        drive_letter = selected_drive.split(" - ")[0]
        self.current_path = drive_letter
        
        self.scanning = True
        self.scan_button.config(state="disabled")
        self.progress_bar.start()
        self.tree.delete(*self.tree.get_children())
        self.file_data.clear()
        
        # Scan in separatem Thread
        scan_thread = threading.Thread(target=self.scan_drive, args=(drive_letter,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def scan_drive(self, drive_path):
        """Scannt das Laufwerk nach großen Dateien"""
        try:
            self.status_var.set(f"Scanne {drive_path}...")
            
            min_size_mb = float(self.min_size_var.get() or 0)
            min_size_bytes = min_size_mb * 1024 * 1024
            
            for root, dirs, files in os.walk(drive_path):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        
                        # Überspringe Systemdateien wenn Schutz aktiviert
                        if self.is_system_file(file_path):
                            continue
                            
                        file_size = os.path.getsize(file_path)
                        
                        if file_size >= min_size_bytes:
                            file_info = {
                                'name': file,
                                'path': file_path,
                                'size': file_size,
                                'size_mb': file_size / (1024 * 1024),
                                'is_system': self.is_system_file(file_path)
                            }
                            self.file_data.append(file_info)
                            
                            # GUI-Update im Hauptthread
                            self.root.after(0, self.update_tree, file_info)
                            
                    except (OSError, IOError):
                        continue  # Überspringen von Dateien ohne Zugriff
                        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Fehler", f"Scan-Fehler: {str(e)}"))
        finally:
            self.root.after(0, self.scan_finished)
    
    def update_tree(self, file_info):
        """Aktualisiert die Treeview mit neuen Dateiinformationen"""
        self.tree.insert("", "end", values=(
            file_info['name'],
            file_info['path'],
            self.format_bytes(file_info['size']),
            f"{file_info['size_mb']:.2f}"
        ))
    
    def scan_finished(self):
        """Wird aufgerufen, wenn der Scan abgeschlossen ist"""
        self.scanning = False
        self.scan_button.config(state="normal")
        self.progress_bar.stop()
        self.delete_button.config(state="normal")
        self.export_button.config(state="normal")
        
        # Sortiere nach Größe (absteigend) - Standard
        self.sort_column_name = "size"
        self.sort_reverse = True
        self.file_data.sort(key=lambda x: x['size'], reverse=True)
        self.update_column_headers()
        self.refresh_tree()
        
        self.status_var.set(f"Scan abgeschlossen. {len(self.file_data)} große Dateien gefunden.")
    
    def sort_column(self, column, reverse):
        """Sortiert die Treeview nach der angegebenen Spalte"""
        if not self.file_data:
            return
        
        # Aktualisiere Sortier-Status
        self.sort_column_name = column
        self.sort_reverse = reverse
        
        # Sortiere die Daten
        if column == "name":
            self.file_data.sort(key=lambda x: x['name'].lower(), reverse=reverse)
        elif column == "path":
            self.file_data.sort(key=lambda x: x['path'].lower(), reverse=reverse)
        elif column == "size":
            self.file_data.sort(key=lambda x: x['size'], reverse=reverse)
        elif column == "size_mb":
            self.file_data.sort(key=lambda x: x['size_mb'], reverse=reverse)
        
        # Aktualisiere Spalten-Header mit Sortierindikatoren
        self.update_column_headers()
        
        # Aktualisiere die Treeview
        self.refresh_tree()
        
        self.status_var.set(f"Sortiert nach {self.get_column_display_name(column)} ({'absteigend' if reverse else 'aufsteigend'})")
    
    def get_column_display_name(self, column):
        """Gibt den Anzeigenamen für eine Spalte zurück"""
        names = {
            "name": "Dateiname",
            "path": "Pfad", 
            "size": "Größe",
            "size_mb": "Größe (MB)"
        }
        return names.get(column, column)
    
    def update_column_headers(self):
        """Aktualisiert die Spalten-Header mit Sortierindikatoren"""
        # Alle Header zurücksetzen
        self.tree.heading("Dateiname", text="Dateiname")
        self.tree.heading("Pfad", text="Pfad")
        self.tree.heading("Größe", text="Größe")
        self.tree.heading("Größe (MB)", text="Größe (MB)")
        
        # Sortierindikator für aktuelle Spalte hinzufügen
        indicator = " ↓" if self.sort_reverse else " ↑"
        
        if self.sort_column_name == "name":
            self.tree.heading("Dateiname", text=f"Dateiname{indicator}")
        elif self.sort_column_name == "path":
            self.tree.heading("Pfad", text=f"Pfad{indicator}")
        elif self.sort_column_name == "size":
            self.tree.heading("Größe", text=f"Größe{indicator}")
        elif self.sort_column_name == "size_mb":
            self.tree.heading("Größe (MB)", text=f"Größe (MB){indicator}")
    
    def refresh_tree(self):
        """Aktualisiert die Treeview mit aktuellen Daten"""
        self.tree.delete(*self.tree.get_children())
        for file_info in self.file_data:
            self.tree.insert("", "end", values=(
                file_info['name'],
                file_info['path'],
                self.format_bytes(file_info['size']),
                f"{file_info['size_mb']:.2f}"
            ))
    
    def apply_filter(self):
        """Wendet Filter auf die Dateiliste an"""
        if not self.file_data:
            return
        
        try:
            min_size_mb = float(self.min_size_var.get() or 0)
            extension_filter = self.extension_var.get().strip().lower()
            
            filtered_data = []
            for file_info in self.file_data:
                # Größenfilter
                if file_info['size_mb'] < min_size_mb:
                    continue
                
                # Erweiterungsfilter
                if extension_filter:
                    file_ext = Path(file_info['name']).suffix.lower().lstrip('.')
                    if extension_filter.lstrip('.') != file_ext:
                        continue
                
                filtered_data.append(file_info)
            
            # Temporär gefilterte Daten anzeigen
            self.tree.delete(*self.tree.get_children())
            for file_info in filtered_data:
                self.tree.insert("", "end", values=(
                    file_info['name'],
                    file_info['path'],
                    self.format_bytes(file_info['size']),
                    f"{file_info['size_mb']:.2f}"
                ))
            
            self.status_var.set(f"Filter angewendet. {len(filtered_data)} Dateien angezeigt.")
            
        except ValueError:
            messagebox.showerror("Fehler", "Ungültige Eingabe für Mindestgröße!")
    
    def delete_selected_files(self):
        """Löscht ausgewählte Dateien"""
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showwarning("Warnung", "Bitte wählen Sie Dateien zum Löschen aus!")
            return
        
        file_paths = []
        total_size = 0
        system_files = []
        
        for item_id in selected_items:
            item = self.tree.item(item_id)
            file_path = item['values'][1]
            
            # Prüfe nochmals auf Systemdateien (Sicherheitscheck)
            if self.is_system_file(file_path):
                system_files.append(os.path.basename(file_path))
                continue
                
            file_paths.append(file_path)
            
            # Berechne Gesamtgröße
            try:
                total_size += os.path.getsize(file_path)
            except:
                pass
        
        # Warnung bei Systemdateien
        if system_files:
            messagebox.showerror(
                "Systemdateien erkannt!", 
                f"Die folgenden Dateien sind systemwichtig und können nicht gelöscht werden:\n\n" +
                "\n".join(system_files[:10]) + 
                (f"\n... und {len(system_files)-10} weitere" if len(system_files) > 10 else "") +
                "\n\nDiese Dateien wurden von der Löschung ausgeschlossen."
            )
        
        if not file_paths:
            messagebox.showwarning("Keine Dateien", "Keine löschbaren Dateien ausgewählt!")
            return
        
        # Bestätigung
        message = f"Möchten Sie {len(file_paths)} Datei(en) löschen?\n"
        message += f"Gesamtgröße: {self.format_bytes(total_size)}\n\n"
        message += "Diese Aktion kann nicht rückgängig gemacht werden!"
        
        if not messagebox.askyesno("Löschen bestätigen", message):
            return
        
        # Dateien löschen
        deleted_count = 0
        failed_files = []
        
        for file_path in file_paths:
            try:
                # Letzte Sicherheitsprüfung
                if self.is_system_file(file_path):
                    failed_files.append((file_path, "Systemdatei - geschützt"))
                    continue
                    
                os.remove(file_path)
                deleted_count += 1
                
                # Aus Datenliste entfernen
                self.file_data = [f for f in self.file_data if f['path'] != file_path]
                
            except Exception as e:
                failed_files.append((file_path, str(e)))
        
        # Ergebnis anzeigen
        if failed_files:
            error_msg = f"{deleted_count} Dateien gelöscht.\n\n"
            error_msg += f"Fehler beim Löschen von {len(failed_files)} Dateien:\n"
            for file_path, error in failed_files[:5]:  # Nur erste 5 Fehler anzeigen
                error_msg += f"• {os.path.basename(file_path)}: {error}\n"
            if len(failed_files) > 5:
                error_msg += f"... und {len(failed_files) - 5} weitere"
            messagebox.showwarning("Teilerfolg", error_msg)
        else:
            messagebox.showinfo("Erfolg", f"{deleted_count} Dateien erfolgreich gelöscht!")
        
        # Treeview aktualisieren
        self.refresh_tree()
        self.status_var.set(f"{len(self.file_data)} Dateien in der Liste.")
    
    def export_list(self):
        """Exportiert die Dateiliste in eine CSV-Datei"""
        if not self.file_data:
            messagebox.showwarning("Warnung", "Keine Daten zum Exportieren!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV-Dateien", "*.csv"), ("Alle Dateien", "*.*")],
            title="Dateiliste speichern"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    f.write("Dateiname,Pfad,Größe (Bytes),Größe (MB)\n")
                    for file_info in self.file_data:
                        f.write(f'"{file_info["name"]}","{file_info["path"]}",'
                               f'{file_info["size"]},{file_info["size_mb"]:.2f}\n')
                
                messagebox.showinfo("Erfolg", f"Dateiliste erfolgreich exportiert:\n{file_path}")
                
            except Exception as e:
                messagebox.showerror("Fehler", f"Export-Fehler: {str(e)}")
    
    def show_context_menu(self, event):
        """Zeigt das Kontextmenü bei Rechtsklick"""
        # Wähle das Element unter dem Mauszeiger aus
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_path(self, event=None):
        """Kopiert den Pfad der ausgewählten Datei in die Zwischenablage"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warnung", "Bitte wählen Sie eine Datei aus!")
            return
        
        item = self.tree.item(selected_item[0])
        file_path = item['values'][1]
        
        # In Zwischenablage kopieren
        self.root.clipboard_clear()
        self.root.clipboard_append(file_path)
        self.root.update()  # Zwischenablage aktualisieren
        
        self.status_var.set(f"Pfad kopiert: {os.path.basename(file_path)}")
    
    def copy_filename(self):
        """Kopiert den Dateinamen der ausgewählten Datei in die Zwischenablage"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warnung", "Bitte wählen Sie eine Datei aus!")
            return
        
        item = self.tree.item(selected_item[0])
        filename = item['values'][0]
        
        # In Zwischenablage kopieren
        self.root.clipboard_clear()
        self.root.clipboard_append(filename)
        self.root.update()
        
        self.status_var.set(f"Dateiname kopiert: {filename}")
    
    def open_in_explorer(self):
        """Öffnet die Datei im Windows Explorer"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warnung", "Bitte wählen Sie eine Datei aus!")
            return
        
        item = self.tree.item(selected_item[0])
        file_path = item['values'][1]
        
        try:
            import subprocess
            subprocess.run(['explorer', '/select,', file_path], check=True)
        except Exception as e:
            messagebox.showerror("Fehler", f"Konnte Explorer nicht öffnen: {str(e)}")
    
    def open_folder_in_explorer(self):
        """Öffnet den Ordner der Datei im Windows Explorer"""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warnung", "Bitte wählen Sie eine Datei aus!")
            return
        
        item = self.tree.item(selected_item[0])
        file_path = item['values'][1]
        folder_path = os.path.dirname(file_path)
        
        try:
            import subprocess
            subprocess.run(['explorer', folder_path], check=True)
        except Exception as e:
            messagebox.showerror("Fehler", f"Konnte Explorer nicht öffnen: {str(e)}")
    
    def clear_filter(self):
        """Setzt alle Filter zurück und zeigt alle Dateien an"""
        self.min_size_var.set("100")
        self.extension_var.set("")
        self.refresh_tree()
        self.status_var.set(f"Filter zurückgesetzt. {len(self.file_data)} Dateien angezeigt.")

def main():
    root = tk.Tk()
    app = DiskAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()