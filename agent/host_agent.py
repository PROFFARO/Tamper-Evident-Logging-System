"""
Host Agent — Real-time System Log Collector

Collects real-time security and system events from the local Windows host
and feeds them into the Tamper-Evident Logging System via its REST API.

Log Sources:
    - Windows Security Event Log (login success/failure via PowerShell)
    - Network connections (active TCP connections, listening ports)
    - Process monitoring (new processes, high-resource processes)
    - System resources (CPU spikes, memory pressure, disk usage)
    - USB / removable device detection

The agent runs as a background thread and pushes events at configurable intervals.
"""

import threading
import time
import json
import subprocess
import platform
import socket
import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Callable

logger = logging.getLogger("host_agent")

# ---------------------------------------------------------------------------
#  Psutil import (optional but highly recommended)
# ---------------------------------------------------------------------------
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not installed — system resource and process monitoring disabled. Install with: pip install psutil")


class HostAgent:
    """
    Real-time host log collector that gathers security-relevant events
    from the local machine and pushes them to a callback function.
    """

    def __init__(self, log_callback: Callable, interval: int = 15):
        """
        Args:
            log_callback: Function(event_type, severity, source, description, metadata)
                          called for each collected event.
            interval: Seconds between collection cycles.
        """
        self._callback = log_callback
        self._interval = interval
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._seen_event_ids: set = set()          # Dedup Windows events
        self._known_connections: set = set()        # Track known network conns
        self._known_pids: set = set()               # Track known processes
        self._last_login_check = datetime.now(timezone.utc).isoformat()
        self._hostname = platform.node()
        self._os_info = f"{platform.system()} {platform.release()}"
        self._cycle_count = 0

    # ── Public API ─────────────────────────────────────────────

    def start(self):
        """Start the agent in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="HostAgent")
        self._thread.start()
        self._emit("SYSTEM_EVENT", "INFO", "host-agent",
                   f"Host agent started on {self._hostname} ({self._os_info})",
                   {"hostname": self._hostname, "os": self._os_info, "interval_sec": self._interval})
        logger.info("Host agent started (interval=%ds)", self._interval)

    def stop(self):
        """Stop the agent."""
        if not self._running:
            return
        self._running = False
        self._emit("SYSTEM_EVENT", "INFO", "host-agent",
                   f"Host agent stopped on {self._hostname}",
                   {"hostname": self._hostname})
        logger.info("Host agent stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def status(self) -> Dict:
        return {
            "running": self._running,
            "hostname": self._hostname,
            "os": self._os_info,
            "interval": self._interval,
            "cycles_completed": self._cycle_count,
            "has_psutil": HAS_PSUTIL,
        }

    # ── Main Loop ──────────────────────────────────────────────

    def _run_loop(self):
        """Main collection loop running in background thread."""
        # Initialize known state on first run
        if HAS_PSUTIL:
            self._known_pids = set(psutil.pids())
            try:
                self._known_connections = {
                    (c.laddr, c.raddr, c.status)
                    for c in psutil.net_connections(kind='tcp')
                    if c.raddr
                }
            except (psutil.AccessDenied, PermissionError):
                self._known_connections = set()

        while self._running:
            try:
                self._collect_cycle()
                self._cycle_count += 1
            except Exception as e:
                logger.error("Collection cycle error: %s", e)
            time.sleep(self._interval)

    def _collect_cycle(self):
        """Run one full collection cycle across all sources."""
        self._collect_windows_login_events()

        if HAS_PSUTIL:
            self._collect_network_events()
            self._collect_process_events()
            self._collect_resource_events()

    # ── Windows Security Event Log ─────────────────────────────

    def _collect_windows_login_events(self):
        """
        Query Windows Security Event Log for recent login events.
        Uses PowerShell Get-WinEvent to fetch:
            4624 = Successful login
            4625 = Failed login
            4634 = Logoff
            4648 = Explicit credential login
        """
        if platform.system() != "Windows":
            return

        try:
            ps_script = (
                "Get-WinEvent -FilterHashtable @{"
                "LogName='Security';"
                "ID=4624,4625,4634,4648;"
                "StartTime=(Get-Date).AddSeconds(-30)"
                "} -MaxEvents 20 -ErrorAction SilentlyContinue | "
                "Select-Object Id,TimeCreated,Message | "
                "ForEach-Object { @{Id=$_.Id;Time=$_.TimeCreated.ToString('o');"
                "Msg=$_.Message.Substring(0,[Math]::Min(300,$_.Message.Length))} } | "
                "ConvertTo-Json -Compress"
            )

            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace"
            )

            if result.returncode != 0 or not result.stdout.strip():
                return

            raw = result.stdout.strip()
            events = json.loads(raw)
            if isinstance(events, dict):
                events = [events]

            event_map = {
                4624: ("LOGIN_SUCCESS", "INFO", "Successful logon"),
                4625: ("LOGIN_FAILURE", "WARNING", "Failed logon attempt"),
                4634: ("LOGOUT", "INFO", "User logoff"),
                4648: ("LOGIN_ATTEMPT", "INFO", "Explicit credential logon"),
            }

            for evt in events:
                evt_id = evt.get("Id")
                evt_time = evt.get("Time", "")
                evt_msg = evt.get("Msg", "")

                # Dedup by time+id combo
                dedup_key = f"{evt_id}_{evt_time}"
                if dedup_key in self._seen_event_ids:
                    continue
                self._seen_event_ids.add(dedup_key)
                # Keep dedup set manageable
                if len(self._seen_event_ids) > 5000:
                    self._seen_event_ids = set(list(self._seen_event_ids)[-2500:])

                etype, severity, label = event_map.get(evt_id, ("SECURITY_ALERT", "WARNING", "Security event"))

                # Extract key info from message
                desc = f"{label}: {evt_msg[:200]}"

                self._emit(etype, severity, "windows-security-log", desc, {
                    "windows_event_id": str(evt_id),
                    "event_time": evt_time,
                    "hostname": self._hostname,
                })

        except subprocess.TimeoutExpired:
            pass
        except json.JSONDecodeError:
            pass
        except Exception as e:
            logger.debug("Windows event collection error: %s", e)

    # ── Network Monitoring ─────────────────────────────────────

    def _collect_network_events(self):
        """Detect new outbound/inbound TCP connections and flag suspicious ports."""
        if not HAS_PSUTIL:
            return

        SUSPICIOUS_PORTS = {4444, 5555, 1234, 31337, 6667, 6697, 8888, 9999, 12345}

        try:
            current_conns = set()
            for c in psutil.net_connections(kind='tcp'):
                # Track both ESTABLISHED connections and active LISTENERS on suspicious ports
                lport = c.laddr.port if c.laddr else 0
                rport = c.raddr.port if c.raddr else 0
                
                is_established = (c.raddr and c.status == 'ESTABLISHED')
                is_suspicious_listener = (c.status == 'LISTEN' and lport in SUSPICIOUS_PORTS)
                
                if is_established or is_suspicious_listener:
                    conn_key = (c.laddr, c.raddr if c.raddr else tuple(), c.status)
                    current_conns.add(conn_key)

                    if conn_key not in self._known_connections:
                        # Determine severity
                        severity = "INFO"
                        event_type = "DATA_ACCESS"
                        
                        if rport in SUSPICIOUS_PORTS or lport in SUSPICIOUS_PORTS:
                            severity = "CRITICAL"
                            event_type = "SECURITY_ALERT"

                        try:
                            proc = psutil.Process(c.pid) if c.pid else None
                            proc_name = proc.name() if proc else "unknown"
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            proc_name = "unknown"

                        local_addr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "unknown"
                        remote_addr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "none"
                        
                        desc = (f"Suspicious port listener detected: {local_addr} (process: {proc_name})" 
                                if is_suspicious_listener else 
                                f"New TCP connection: {local_addr} → {remote_addr} (process: {proc_name})")

                        self._emit(event_type, severity, "network-monitor", desc,
                                   {"local": local_addr, "remote": remote_addr,
                                    "process": proc_name, "pid": str(c.pid or 0), "state": c.status})

            self._known_connections = current_conns

        except (psutil.AccessDenied, PermissionError):
            pass
        except Exception as e:
            logger.debug("Network collection error: %s", e)

    # ── Process Monitoring ─────────────────────────────────────

    def _collect_process_events(self):
        """Detect new process launches since last cycle."""
        if not HAS_PSUTIL:
            return

        try:
            current_pids = set(psutil.pids())
            new_pids = current_pids - self._known_pids

            for pid in list(new_pids)[:10]:  # Cap at 10 per cycle
                try:
                    proc = psutil.Process(pid)
                    pinfo = proc.as_dict(attrs=['name', 'username', 'exe', 'cmdline', 'create_time'])
                    name = pinfo.get('name', 'unknown')
                    user = pinfo.get('username', 'unknown')
                    exe = pinfo.get('exe', 'unknown') or 'unknown'

                    # Skip common system noise
                    skip_names = {'svchost.exe', 'conhost.exe', 'RuntimeBroker.exe',
                                  'backgroundTaskHost.exe', 'SearchProtocolHost.exe',
                                  'SearchFilterHost.exe', 'dllhost.exe', 'WmiPrvSE.exe',
                                  'taskhostw.exe', 'sihost.exe', 'ctfmon.exe',
                                  'TextInputHost.exe', 'SystemSettings.exe'}
                    if name in skip_names:
                        continue

                    self._emit("USER_ACTIVITY", "INFO", "process-monitor",
                               f"New process launched: {name} (PID: {pid}, user: {user})",
                               {"pid": str(pid), "name": name, "user": user or "unknown",
                                "exe": str(exe)[:200]})

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            self._known_pids = current_pids

        except Exception as e:
            logger.debug("Process collection error: %s", e)

    # ── System Resource Monitoring ─────────────────────────────

    def _collect_resource_events(self):
        """Monitor CPU, memory, and disk — alert on abnormal thresholds."""
        if not HAS_PSUTIL:
            return

        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            # High CPU alert
            if cpu_percent > 85:
                severity = "CRITICAL" if cpu_percent > 95 else "WARNING"
                self._emit("SYSTEM_EVENT", severity, "resource-monitor",
                           f"High CPU utilization detected: {cpu_percent:.1f}%",
                           {"cpu_percent": f"{cpu_percent:.1f}", "hostname": self._hostname})

            # High memory alert
            if mem.percent > 85:
                severity = "CRITICAL" if mem.percent > 95 else "WARNING"
                used_gb = mem.used / (1024**3)
                total_gb = mem.total / (1024**3)
                self._emit("SYSTEM_EVENT", severity, "resource-monitor",
                           f"High memory utilization: {mem.percent:.1f}% ({used_gb:.1f}GB / {total_gb:.1f}GB)",
                           {"memory_percent": f"{mem.percent:.1f}",
                            "used_gb": f"{used_gb:.1f}", "total_gb": f"{total_gb:.1f}"})

            # Low disk space alert
            if disk.percent > 90:
                free_gb = disk.free / (1024**3)
                self._emit("SYSTEM_EVENT", "WARNING", "resource-monitor",
                           f"Low disk space: {disk.percent:.1f}% used ({free_gb:.1f}GB free)",
                           {"disk_percent": f"{disk.percent:.1f}", "free_gb": f"{free_gb:.1f}"})

            # Periodic system health snapshot (every 4th cycle)
            if self._cycle_count % 4 == 0 and self._cycle_count > 0:
                boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
                uptime = datetime.now(timezone.utc) - boot_time
                uptime_str = f"{uptime.days}d {uptime.seconds // 3600}h {(uptime.seconds % 3600) // 60}m"

                net_io = psutil.net_io_counters()
                sent_mb = net_io.bytes_sent / (1024**2)
                recv_mb = net_io.bytes_recv / (1024**2)

                self._emit("SYSTEM_EVENT", "INFO", "resource-monitor",
                           f"System health: CPU {cpu_percent:.1f}%, RAM {mem.percent:.1f}%, "
                           f"Disk {disk.percent:.1f}%, Uptime {uptime_str}",
                           {"cpu": f"{cpu_percent:.1f}", "ram": f"{mem.percent:.1f}",
                            "disk": f"{disk.percent:.1f}", "uptime": uptime_str,
                            "net_sent_mb": f"{sent_mb:.1f}", "net_recv_mb": f"{recv_mb:.1f}"})

        except Exception as e:
            logger.debug("Resource collection error: %s", e)

    # ── Emitter ────────────────────────────────────────────────

    def _emit(self, event_type: str, severity: str, source: str,
              description: str, metadata: Optional[Dict] = None):
        """Send a collected event to the logging system."""
        try:
            self._callback(
                event_type=event_type,
                severity=severity,
                source=source,
                description=description,
                metadata=metadata or {}
            )
        except Exception as e:
            logger.error("Failed to emit event: %s", e)
