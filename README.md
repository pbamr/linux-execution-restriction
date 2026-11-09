

# Safer – Kernel-Based Access Control System (LSM)

**Version:** 1.0  
**Date:** November 2026  
**Author:** Peter Boettcher  
**License:** GPLv2  

Safer is a highly secure, kernel-based access control system (Linux Security Module) designed to protect both the base operating system and container runtimes from unauthorized file executions, tampered scripts, and unapproved network or file operations – even if an attacker has already obtained administrative (`root`) privileges.

---

## 1. Key Features

*   **Program Verification:** Validates binary files based on absolute path, SHA256 hash, and UID/GID.
*   **Script Verification:** Integrity checking for scripts (both with and without a shebang) via hash comparison.
*   **Interpreter Coupling (`ai:`):** Restrictive lock mechanism ensuring that interpreters can only be invoked for explicitly allowed scripts.
*   **Library Verification (`so:`):** Runtime validation of Shared Objects before they are loaded into memory.
*   **Kernel Module Protection:** Global deactivation of `init_module` alongside a selective whitelist for trusted modules.
*   **Shell Inline Protection:** Blocks inline code passed directly to shells.
*   **Configuration Protection:** Continuous self-integrity monitoring using hash and content verification.
*   **SCS (Socket Connect Send):** Context-aware restriction of network address families for both host and container.
*   **OPEN (File Block Protection):** Targeted blocking of file-open operations based on context and user for incident response and debugging.
*   **Granular Learning Mode:** Independently controllable rule generation for all subsystems directly via the `/proc` filesystem.

---

## 2. Installation & Integration

### 2.1 Kernel Compilation
Integrate the Safer patch into your kernel source tree and activate the module using the kernel configuration menu:
```bash
make menuconfig
# Enable under: Security options -> Safer Kernel Access Control
# CONFIG_SECURITY_SAFER=y
```

### 2.2 Boot Protection (initramfs)
To secure the system from the very first second, embed the configuration file into the `initramfs`. This ensures the rule set is loaded before `systemd` or other user-space processes start.

### 2.3 Static Integration
For high-security systems, the validation whitelists can be statically compiled directly into the kernel image. This renders any subsequent modifications to the local filesystem completely ineffective against the whitelist.

---

## 3. Configuration Syntax (`rules.conf`)

The configuration file utilizes strict, line-based prefixes. Parameters are separated by semicolons (`;`).

### 3.1 Rule Formats

| Prefix / Format | Description |
| :--- | :--- |
| `a:<UID>;<Size>;<Hash>;<Path>` | Allow program or script for a specific UID. |
| `a:*;<Size>;<Hash>;<Path>` | Globally allow a program for all users. |
| `d:<UID>;<Size>;<Hash>;<Path>` | Specifically forbid a program for a single UID. |
| `d:*;<Size>;<Hash>;<Path>` | Globally block a program for all users. |
| `d:<Path/>` | Block an entire directory (recognized by trailing `/`). |
| `ai:<UID>;<Size>;<Hash>;<Interpreter>` | Bind interpreter coupling to allowed scripts. |
| `SHELL-INLINE:<UID>;<Shell>;<1/0>` | Enable (1) or block (0) shell inline code for a UID. |
| `KONFIG:<Size>;<Hash>;<Path>` | Hash monitoring of the Safer configuration file itself. |
| `KONFIG_SFILE:<Path>;<Content_Hash>` | Content verification for critical system files. |
| `so:<Size>;<Hash>;<Path>` | Allow a Shared Object (.so library). |
| `mod:<Size>;<Hash>;<Name>` | Allow loading of a specific kernel module. |
| `SCS:HOST:a:<UID>;<Path>;<ID>` | Allow a network address family on the host context. |
| `SCS:CONT:a:<UID>;<Path>;<ID>` | Allow a network address family in the container context. |
| `OPEN:HOST:<UID>;<Path>` | Block file opening on the host for this UID (Debug). |
| `OPEN:CONT:<UID>;<Path>` | Block file opening in the container for this UID (Debug). |

### 3.2 Numeric Address Families (SCS Reference)
*   `1` = `AF_UNIX` / `AF_LOCAL` (Local Sockets)
*   `2` = `AF_INET` (IPv4 Internet Protocol)
*   `10` = `AF_INET6` (IPv6 Internet Protocol)
*   `16` = `AF_NETLINK` (Kernel-User-Space Communication)

### 3.3 Configuration Example
```ini
# Allow Python3 for user 1000
a:1000;142304;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;/usr/bin/python3

# Globally forbid netcat for all users
d:*;32416;7f83b1657ff1fc53b92c4736b1f23432427ae41e4649b934ca495991b7852b855;/bin/nc

# Block an entire directory
d:/tmp/bad_exec/

# SCS: Allow nginx on the host to use IPv4 (2) and IPv6 (10) only
SCS:HOST:a:80;/usr/sbin/nginx;2
SCS:HOST:a:80;/usr/sbin/nginx;10

# SCS: Allow container app to use local UNIX sockets (1) only
SCS:CONT:a:1001;/app/backend;1

# OPEN: Block UID 1000 from accessing debug logs in the container context
OPEN:CONT:1000;/var/log/app_debug.log
```

---

## 4. Administration using `bsafer.sh`

The `bsafer.sh` utility serves as the CLI interface for kernel management:

*   **Load rules:**
    ```bash
    bsafer.sh --load /etc/safer/rules.conf
    ```
*   **Enable learning mode:**
    ```bash
    bsafer.sh --learning on
    ```
*   **Disable learning mode:**
    ```bash
    bsafer.sh --learning off
    ```
*   **Export generated whitelist:**
    ```bash
    bsafer.sh --export > /etc/safer/rules.conf
    ```
*   **Query protection status:**
    ```bash
    bsafer.sh --status
    ```

---

## 5. Operating Modes & Workflows

### 5.1 Recommended Deployment Workflow
1. **Initiate Learning Phase:** Switch Safer into learning mode: `bsafer.sh --learning on`.
2. **Train the System:** Fully execute all intended applications, CI/CD pipelines, cron jobs, and network connections. The kernel automatically records authorized paths and SCS contexts.
3. **Save Rule Set:** Export the generated whitelist (`bsafer.sh --export`).
4. **Activate Enforcing Mode:** Turn off learning mode (`bsafer.sh --learning off`) to arm the protection system.

### 5.2 Performance Warning regarding OPEN Rules
> ⚠️ **ATTENTION:** Enabling the learning mode for file operations (`/proc/safer.open.learning`) causes **massive performance degradation and system slowdowns** under high I/O workloads. This occurs because every single file interaction (`sys_open`/`sys_openat`) must be intercepted and processed by the kernel. Only use the open-learning mode temporarily and for focused debugging!

---

## 6. Kernel Interfaces (`/proc`)

The Safer subsystem communicates directly with user-space via the `/proc` filesystem. Operations and logging are handled exclusively through the following virtual files in the root directory:

### 6.1 Base & Program Control
*   **/proc/safer.info**  
    Outputs current subsystem states, statistics, and the real-time violations log (includes timestamp, UID, path, and violated rule type).
*   **/proc/safer.learning**  
    Global toggle for the base learning mode. Running `echo 1 > /proc/safer.learning` enables recording of programs and SCS connections. `0` sets the system to enforcing mode.

### 6.2 Shared Objects (Libraries)
*   **/proc/safer.lib.info**  
    Displays status info and loaded rules regarding shared object validation (`so:`).
*   **/proc/safer.lib.learning**  
    Independent toggle (`1`/`0`) for shared object learning. Allows isolated capture of library dependencies to prevent boot-time performance bottlenecks.

### 6.3 File Openings (OPEN Protection)
*   **/proc/safer.open.info**  
    Lists currently active path restrictions for host/container contexts and logged open violations.
*   **/proc/safer.open.learning**  
    Toggle (`1`/`0`) for the high-overhead file-open protection learning mode (`OPEN:`).

### 6.4 Kernel Modules
*   **/proc/safer.module.info**  
    Displays the lock state of the kernel module loader (`init_module`) and the allowed modules list.
*   **/proc/safer.module.learning**  
    Toggle (`1`/`0`) to automatically record trusted kernel modules during hardware discovery and initial system boot.

---

## 7. Container and Host Isolation
Safer features built-in **context detection** via namespaces (e.g., `pid`, `net`, `mnt`) to precisely distinguish between base host operations and container environments (Docker, LXC, etc.).

*   **Host Level (`SCS:HOST:a:` / `OPEN:HOST:`):** Monitors network and file access directly on the base OS. This allows administrators to lock down system daemons to required protocols (e.g., `2` for IPv4) and protects internal communication paths (like Netlink) from abuse.
*   **Container Level (`SCS:CONT:a:` / `OPEN:CONT:`):** Recognizes isolated namespaces. If an application inside a container tries to open forbidden sockets or access file paths blocked via `OPEN:CONT:`, the kernel blocks the syscall instantly, returning `EACCES` (`Permission denied`).

---

## 8. Glossary
*   **Shebang:** The first line of a script file (e.g., `#!/bin/bash`) specifying its interpreter.
*   **Allow-List (Whitelist):** A list of hashes, paths, and operational rules explicitly permitted to run by the kernel.
*   **SCS (Socket Connect Send):** The networking access control engine filtering actions during socket creation (`socket`), endpoint connection (`connect`), and data transmission (`send`/`sendto`).
*   **OPEN (File Block Protection):** A component used for context-based blocking of file opening commands (`sys_open`/`sys_openat`) for isolation and debugging.
*   **Address Family (Numeric):** Internal kernel identifiers for network protocols (e.g., `1` = AF_UNIX, `2` = AF_INET, `10` = AF_INET6, `16` = AF_NETLINK).

---

## 9. Security & Safety Guidelines

*   **Cryptographic Integrity:** Safer strictly mandates the SHA256 algorithm.



# Safer – Kernel-basiertes Zugriffskontrollsystem (LSM)

**Version:** 1.0  
**Datum:** November 2026  
**Autor:** Peter Boettcher  
**Lizenz:** GPLv2  

Safer ist ein hochsicheres, Kernel-basiertes Zugriffskontrollsystem (Linux Security Module), das das Betriebssystem sowie Container-Laufzeiten vor unautorisierten Dateiausführungen, manipulierten Skripten und unerlaubten Netzwerk- oder Dateizugriffen schützt – selbst wenn ein Angreifer bereits administrative Rechte (`root`) erlangt hat.

---

## 1. Hauptfunktionen

*   **Programmprüfung:** Validierung von Binärdateien anhand von absolutem Pfad, SHA256-Hash und UID/GID.
*   **Skriptprüfung:** Integritätsprüfung von Skripten (sowohl mit als auch ohne Shebang) via Hash-Abgleich.
*   **Interpreter-Kopplung (`ai:`):** Restriktive Sperre, die sicherstellt, dass Interpreter nur für explizit freigegebene Skripte aufgerufen werden dürfen.
*   **Bibliotheksprüfung (`so:`):** Laufzeit-Validierung von Shared Objects vor dem Laden in den Speicher.
*   **Kernel-Modul-Schutz:** Globale Deaktivierung von `init_module` und selektive Whitelist für vertrauenswürdige Module.
*   **Shell-Inline-Schutz:** Blockierung von direkt übergebenem Inline-Code in Shells.
*   **Konfigurationsschutz:** Laufende Überwachung der eigenen Integrität mittels Hash- und Inhaltsprüfung.
*   **SCS (Socket Connect Send):** Kontextabhängige Absicherung von Netzwerk-Adressfamilien für Host und Container.
*   **OPEN (Datei-Sperrschutz):** Gezieltes Blockieren von Dateiöffnungen nach Kontext und Benutzer für Incident Response und Debugging.
*   **Granularer Learning Mode:** Getrennt steuerbare Erfassung der Regelsätze für alle Teilsysteme direkt über das `/proc`-Dateisystem.

---

## 2. Installation & Integration

### 2.1 Kernel-Kompilierung
Integrieren Sie den Safer-Patch in Ihren Kernel-Quellbaum und aktivieren Sie das Modul über die Kernelkonfiguration:
```bash
make menuconfig
# Aktivieren unter: Security options -> Safer Kernel Access Control
# CONFIG_SECURITY_SAFER=y
```

### 2.2 Boot-Schutz (initramfs)
Um das System ab der ersten Sekunde zu schützen, betten Sie die Konfigurationsdatei in die `initramfs` ein. Dadurch wird das Regelwerk geladen, bevor `systemd` oder andere User-Space-Prozesse starten.

### 2.3 Statische Integration
Für Hochsicherheitssysteme können die Validierungslisten direkt fest in das Kernel-Image einkompiliert werden. Änderungen am lokalen Dateisystem sind damit wirkungslos gegen die Whitelist.

---

## 3. Konfigurationssyntax (`rules.conf`)

Die Steuerdatei verwendet strikte, zeilenbasierte Präfixe. Die Parameter werden per Semikolon (`;`) getrennt.

### 3.1 Regel-Formate

| Präfix / Format | Beschreibung |
| :--- | :--- |
| `a:<UID>;<Größe>;<Hash>;<Pfad>` | Programm oder Skript für spezifische UID erlauben. |
| `a:*;<Größe>;<Hash>;<Pfad>` | Programm global für alle Benutzer freigeben. |
| `d:<UID>;<Größe>;<Hash>;<Pfad>` | Programm gezielt für eine UID verbieten. |
| `d:*;<Größe>;<Hash>;<Pfad>` | Programm global für alle Benutzer sperren. |
| `d:<Pfad/>` | Ganzen Ordner sperren (erkannt durch `/` am Ende). |
| `ai:<UID>;<Größe>;<Hash>;<Interpreter>` | Interpreter-Kopplung an erlaubte Skripte binden. |
| `SHELL-INLINE:<UID>;<Shell>;<1/0>` | Shell-Inline-Code für UID aktivieren (1) oder blockieren (0). |
| `KONFIG:<Größe>;<Hash>;<Pfad>` | Hash-Überwachung der Safer-Konfigurationsdatei selbst. |
| `KONFIG_SFILE:<Pfad>;<Inhalt_Hash>` | Inhaltsprüfung für kritische Systemdateien. |
| `so:<Größe>;<Hash>;<Pfad>` | Shared Object (.so-Bibliothek) freigeben. |
| `mod:<Größe>;<Hash>;<Name>` | Laden des spezifischen Kernel-Moduls erlauben. |
| `SCS:HOST:a:<UID>;<Pfad>;<ID>` | Netzwerk-Adressfamilie auf dem Host herstellerabhängig erlauben. |
| `SCS:CONT:a:<UID>;<Pfad>;<ID>` | Netzwerk-Adressfamilie im Container erlauben. |
| `OPEN:HOST:<UID>;<Pfad>` | Dateiöffnung auf dem Host für diese UID verbieten (Debug). |
| `OPEN:CONT:<UID>;<Pfad>` | Dateiöffnung im Container für diese UID verbieten (Debug). |

### 3.2 Numerische Adressfamilien (SCS-Referenz)
*   `1` = `AF_UNIX` / `AF_LOCAL` (Lokale Sockets)
*   `2` = `AF_INET` (IPv4 Internet Protokoll)
*   `10` = `AF_INET6` (IPv6 Internet Protokoll)
*   `16` = `AF_NETLINK` (Kernel-User-Space-Kommunikation)

### 3.3 Konfigurationsbeispiel
```ini
# Erlaube Python3 für Benutzer 1000
a:1000;142304;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855;/usr/bin/python3

# Verbiete Netcat global für alle User
d:*;32416;7f83b1657ff1fc53b92c4736b1f23432427ae41e4649b934ca495991b7852b855;/bin/nc

# Gesamtes Verzeichnis sperren
d:/tmp/bad_exec/

# SCS: Erlaube nginx auf dem Host nur IPv4 (2) und IPv6 (10)
SCS:HOST:a:80;/usr/sbin/nginx;2
SCS:HOST:a:80;/usr/sbin/nginx;10

# SCS: Erlaube der Container-Anwendung nur lokale UNIX-Sockets (1)
SCS:CONT:a:1001;/app/backend;1

# OPEN: Blockiere im Container-Kontext den Zugriff auf die Debug-Logs für UID 1000
OPEN:CONT:1000;/var/log/app_debug.log
```

---

## 4. Administration mit `bsafer.sh`

Das Dienstprogramm `bsafer.sh` dient als CLI-Schnittstelle zur Kernel-Steuerung:

*   **Regelwerk laden:**
    ```bash
    bsafer.sh --load /etc/safer/rules.conf
    ```
*   **Lernmodus aktivieren:**
    ```bash
    bsafer.sh --learning on
    ```
*   **Lernmodus deaktivieren:**
    ```bash
    bsafer.sh --learning off
    ```
*   **Generierte Whitelist exportieren:**
    ```bash
    bsafer.sh --export > /etc/safer/rules.conf
    ```
*   **Schutzstatus abfragen:**
    ```bash
    bsafer.sh --status
    ```

---

## 5. Betriebsmodi & Workflows

### 5.1 Empfohlener Deployment-Workflow
1. **Lernphase einleiten:** Schalten Sie Safer in den Lernmodus: `bsafer.sh --learning on`.
2. **System trainieren:** Führen Sie alle vorgesehenen Applikationen, CI/CD-Pipelines, Cronjobs und Netzwerkverbindungen einmal vollständig aus. Der Kernel schreibt erlaubte Pfade und SCS-Kontexte automatisch mit.
3. **Regelsatz sichern:** Exportieren Sie die generierte Whitelist (`bsafer.sh --export`).
4. **Enforcing Mode aktivieren:** Schalten Sie den Lernmodus ab (`bsafer.sh --learning off`), um das System scharfzuschalten.

### 5.2 Performance-Warnung zu OPEN-Regeln
> ⚠️ **ACHTUNG:** Die Aktivierung des Lernmodus für Dateioperationen (`/proc/safer.open.learning`) führt bei Systemen mit hoher I/O-Last zu **massiven Performance-Einbußen und spürbarer Verlangsamung**, da jede Dateiinteraktion (`sys_open`/`sys_openat`) im Kernel abgefangen und verarbeitet werden muss. Nutzen Sie den Open-Lernmodus ausschließlich kurzzeitig und fokussiert für gezielte Debug-Analysen!

---

## 6. Kernel-Schnittstellen (`/proc`)

Über das `/proc`-Dateisystem kommuniziert das Safer-Subsystem direkt mit dem User-Space. Die Steuerung und Protokollierung erfolgt ausschließlich über folgende virtuelle Dateien im Hauptverzeichnis:

### 6.1 Basis- & Programmsteuerung
*   **/proc/safer.info**  
    Gibt den aktuellen System-Gesamtzustand, Statistiken sowie das Echtzeit-Protokoll blockierter Zugriffsversuche aus (Zeitstempel, UID, Pfad und verletzter Regel-Typ).
*   **/proc/safer.learning**  
    Globaler Schalter für den Basis-Lernmodus. Ein `echo 1 > /proc/safer.learning` aktiviert das Mitloggen von Standard-Programmen und SCS-Netzwerkverbindungen. Eine `0` schaltet den Schutz scharf.

### 6.2 Shared Objects (Bibliotheken)
*   **/proc/safer.lib.info**  
    Zeigt Statusinformationen und geladene Regeln bezüglich der Bibliotheksprüfung (`so:`).
*   **/proc/safer.lib.learning**  
    Separater Schalter (`1`/`0`) für den Lernmodus der Shared Objects. Ermöglicht die isolierte Erfassung von Bibliotheks-Abhängigkeiten, um die Performance beim Systemstart zu entkoppeln.

### 6.3 Dateiöffnungen (OPEN-Schutz)
*   **/proc/safer.open.info**  
    Listet die aktuell aktiven Pfadsperren für den Host- und Container-Kontext sowie protokollierte Verletzungen auf.
*   **/proc/safer.open.learning**  
    Schalter (`1`/`0`) für den I/O-intensiven Lernmodus des Datei-Sperrschutzes (`OPEN:`).

### 6.4 Kernel-Module
*   **/proc/safer.module.info**  
    Zeigt den Sperrzustand des Kernel-Modulladers (`init_module`) sowie die Liste der erlaubten Module.
*   **/proc/safer.module.learning**  
    Schalter (`1`/`0`) zur automatischen Erfassung vertrauenswürdiger Kernel-Module während der Hardware-Erkennung und des Systemstarts.

---

## 7. Container und Host
Safer besitzt eine **Kontexterkennung**, die via Namespaces (z.B. `pid`, `net`, `mnt`) präzise zwischen Prozessen auf dem Host und innerhalb von Containern (Docker, LXC, etc.) unterscheidet.

*   **Host-Ebene (`SCS:HOST:a:` / `OPEN:HOST:`):** Überwacht Netzwerk- und Dateizugriffe direkt auf dem Basis-Betriebssystem. Ermöglicht es, System-Diensten gezielt nur die benötigten Protokolle (z. B. `2` für IPv4) zuzuweisen und interne Kommunikationskanäle (wie Netlink) vor Missbrauch zu schützen.
*   **Container-Ebene (`SCS:CONT:a:` / `OPEN:CONT:`):** Erkennt isolierte Namespaces. Versucht eine Anwendung im Container, verbotene Sockets zu öffnen oder auf mittels `OPEN:CONT:` gesperrte Pfade zuzugreifen, fängt der Kernel den Aufruf ab und blockiert die Operation sofort mit `EACCES` (`Permission denied`).

---

## 8. Glossar
*   **Shebang:** Die erste Zeile eines Skripts (z.B. `#!/bin/bash`), die den Interpreter definiert.
*   **Allow-Liste (Whitelist):** Eine Liste von Hashes, Pfaden und Regeln, die explizit vom Kernel ausgeführt oder verwendet werden dürfen.
*   **SCS (Socket Connect Send):** Das Teilsystem zur netzwerkseitigen Zugriffskontrolle, das Systemaufrufe beim Erstellen (`socket`), Verbinden (`connect`) und Senden (`send`/`sendto`) filtert.
*   **OPEN (Datei-Sperrschutz):** Ein Subsystem zur kontextbasierten Sperrung von Dateiöffnungen (`sys_open`/`sys_openat`) für Debugging und restriktive Isolation.
*   **Address Family (Numeric):** Internal Kernel Identifikation für folgende Protokolle (e.g., `1` = AF_UNIX, `2` = AF_INET, `10` = AF_INET6, `16` = AF_NETLINK).
