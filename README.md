# Disk Scanner

Ein leistungsfähiges Tool zur Analyse von Festplatten und zum Auffinden großer Dateien unter Windows.

## 🚀 Features

- **Laufwerksanalyse**: Scannt beliebige Laufwerke nach großen Dateien
- **Intelligente Filterung**: 
  - Filtert nach Dateigröße
  - Filtert nach Dateierweiterungen
  - Systemdateien-Schutz (optional)
- **Sortierung**: 
  - Nach Dateigröße
  - Nach Dateiname
  - Nach Dateipfad
- **Dateioperationen**:
  - Dateien sicher löschen
  - Dateiliste als CSV exportieren
- **Kontextmenü-Funktionen**:
  - Pfad in Zwischenablage kopieren
  - Dateinamen in Zwischenablage kopieren
  - Im Explorer öffnen
  - Ordner im Explorer öffnen
- **Systemschutz**:
  - Integrierter Schutz für Windows-Systemdateien
  - Verhindert versehentliches Löschen wichtiger Dateien

## 📋 Voraussetzungen

- Windows 10/11
- Python 3.7 oder höher
- Benötigte Python-Pakete:
  - tkinter (in Python Standard-Installation enthalten)
  - psutil (`pip install psutil`)

## 🛠️ Installation

1. Stellen Sie sicher, dass Python 3.7+ installiert ist
2. Installieren Sie die benötigten Pakete:
   ```bash
   pip install psutil
   ```
3. Laden Sie den Scanner herunter
4. Starten Sie die Anwendung:
   ```bash
   python Scanner.py
   ```

## 💡 Verwendung

1. **Laufwerk auswählen**:
   - Wählen Sie das zu scannende Laufwerk aus der Dropdown-Liste
   - Klicken Sie auf "Scannen"

2. **Filter anwenden**:
   - Minimale Dateigröße in MB einstellen
   - Optional: Dateierweiterung eingeben (z.B. "mp4")
   - "Filter anwenden" klicken

3. **Mit Ergebnissen arbeiten**:
   - Dateien durch Klicken auswählen
   - Rechtsklick für Kontextmenü
   - Strg+Klick für Mehrfachauswahl

4. **Dateien löschen**:
   - Dateien auswählen
   - "Ausgewählte Dateien löschen" klicken
   - Löschvorgang bestätigen

5. **Liste exportieren**:
   - "Liste exportieren" klicken
   - Speicherort für CSV-Datei wählen

## ⚠️ Sicherheitshinweise

- Der Systemdateien-Schutz sollte aktiviert bleiben
- Deaktivieren Sie den Schutz nur, wenn Sie genau wissen, was Sie tun
- Prüfen Sie vor dem Löschen die ausgewählten Dateien sorgfältig
- Erstellen Sie Backups wichtiger Daten

## 🔒 Systemdateien-Schutz

Der integrierte Schutz verhindert das Löschen von:
- Windows-Systemdateien
- Programmdateien
- Versteckten Systemdateien
- Kritischen Systemordnern

![image](https://github.com/user-attachments/assets/b64b8d6b-ebce-4226-8317-3ab44064f953)
