"""
PortGuard - Monitor Engine
Orchestrates continuous scanning, change detection, and event dispatch.
"""

import time
import threading
import logging
from datetime import datetime
from typing import Callable, List, Optional

from core.port_scanner import PortScanner, PortInfo

logger = logging.getLogger("portguard.monitor")


class MonitorEvent:
    """Represents a monitoring event (port opened, closed, etc.)."""

    EVENT_PORT_OPENED = "PORT_OPENED"
    EVENT_PORT_CLOSED = "PORT_CLOSED"
    EVENT_SCAN_COMPLETE = "SCAN_COMPLETE"

    def __init__(self, event_type: str, port_info: Optional[PortInfo] = None,
                 message: str = "", extra: dict = None):
        self.event_type = event_type
        self.port_info = port_info
        self.message = message
        self.extra = extra or {}
        self.timestamp = datetime.now()

    def __repr__(self):
        return f"MonitorEvent({self.event_type}, port={self.port_info.port if self.port_info else None})"


class MonitorEngine:
    """
    Background monitoring engine.
    Runs continuous port scans and fires events to registered listeners.
    """

    def __init__(self, scan_interval: int = 5):
        self.scan_interval = scan_interval
        self._scanner = PortScanner()
        self._listeners: List[Callable[[MonitorEvent], None]] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_count = 0
        self._start_time: Optional[datetime] = None
        self._lock = threading.Lock()
        self._current_ports = {}
        self._stats = {
            "scans_performed": 0,
            "ports_opened": 0,
            "ports_closed": 0,
            "threats_detected": 0,
        }
        logger.info(f"MonitorEngine initialized (interval={scan_interval}s)")

    def register_listener(self, callback: Callable[[MonitorEvent], None]):
        """Register a callback that will be called for each monitor event."""
        self._listeners.append(callback)
        logger.debug(f"Registered listener: {callback.__name__}")

    def _emit(self, event: MonitorEvent):
        """Dispatch event to all registered listeners."""
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as e:
                logger.error(f"Listener error: {e}")

    def _scan_loop(self):
        """Main scan loop — runs in background thread."""
        logger.info("Monitor scan loop started.")
        # Initial baseline scan
        self._current_ports = self._scanner.scan()
        logger.info(f"Baseline scan: {len(self._current_ports)} ports found.")

        while self._running:
            time.sleep(self.scan_interval)
            try:
                current = self._scanner.scan()
                changes = self._scanner.get_changes(current)

                with self._lock:
                    self._current_ports = current
                    self._stats["scans_performed"] += 1
                    self._scan_count += 1

                # Emit events for newly opened ports
                for port_info in changes["new"]:
                    self._stats["ports_opened"] += 1
                    event = MonitorEvent(
                        event_type=MonitorEvent.EVENT_PORT_OPENED,
                        port_info=port_info,
                        message=f"New port detected: {port_info.port}/{port_info.protocol} "
                                f"({port_info.process_name or 'unknown'})"
                    )
                    logger.info(event.message)
                    self._emit(event)

                # Emit events for closed ports
                for port_info in changes["closed"]:
                    self._stats["ports_closed"] += 1
                    event = MonitorEvent(
                        event_type=MonitorEvent.EVENT_PORT_CLOSED,
                        port_info=port_info,
                        message=f"Port closed: {port_info.port}/{port_info.protocol}"
                    )
                    logger.info(event.message)
                    self._emit(event)

                # Emit scan-complete summary
                self._emit(MonitorEvent(
                    event_type=MonitorEvent.EVENT_SCAN_COMPLETE,
                    message=f"Scan #{self._scan_count}: {len(current)} ports active, "
                            f"{len(changes['new'])} new, {len(changes['closed'])} closed"
                ))

            except Exception as e:
                logger.error(f"Scan loop error: {e}", exc_info=True)

    def start(self):
        """Start the background monitoring thread."""
        if self._running:
            logger.warning("MonitorEngine is already running.")
            return
        self._running = True
        self._start_time = datetime.now()
        self._thread = threading.Thread(target=self._scan_loop, daemon=True, name="PortGuardMonitor")
        self._thread.start()
        logger.info("MonitorEngine started.")

    def stop(self):
        """Stop the monitoring thread gracefully."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        logger.info("MonitorEngine stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def uptime(self) -> str:
        if not self._start_time:
            return "Not started"
        delta = datetime.now() - self._start_time
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m, s = divmod(rem, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    @property
    def current_ports(self) -> dict:
        with self._lock:
            return dict(self._current_ports)

    @property
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def increment_threat_count(self):
        with self._lock:
            self._stats["threats_detected"] += 1
