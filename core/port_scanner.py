"""
PortGuard - Port Scanner Core
Handles real-time port discovery and state tracking.
"""

import psutil
import socket
import logging
from datetime import datetime
from typing import Dict, Set, List, Optional

logger = logging.getLogger("portguard.scanner")


class PortInfo:
    """Represents information about a single open port."""

    def __init__(self, port: int, protocol: str, pid: Optional[int],
                 process_name: Optional[str], local_address: str,
                 remote_address: Optional[str] = None, status: str = "OPEN"):
        self.port = port
        self.protocol = protocol
        self.pid = pid
        self.process_name = process_name
        self.local_address = local_address
        self.remote_address = remote_address
        self.status = status
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "pid": self.pid,
            "process_name": self.process_name,
            "local_address": self.local_address,
            "remote_address": self.remote_address,
            "status": self.status,
            "first_seen": self.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": self.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def __repr__(self):
        return (f"PortInfo(port={self.port}, protocol={self.protocol}, "
                f"process={self.process_name}, status={self.status})")


class PortScanner:
    """
    Real-time port scanner using psutil to enumerate listening/connected ports.
    Tracks state changes between scans.
    """

    def __init__(self):
        self._previous_ports: Dict[int, PortInfo] = {}
        self._hostname = socket.gethostname()
        logger.info(f"PortScanner initialized on host: {self._hostname}")

    def scan(self) -> Dict[int, PortInfo]:
        """
        Perform a full port scan and return current open ports.
        Returns a dict keyed by port number.
        """
        current_ports: Dict[int, PortInfo] = {}

        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            logger.warning("Access denied when fetching connections. Try running as root.")
            return current_ports

        for conn in connections:
            if conn.laddr and conn.status in ("LISTEN", "ESTABLISHED", "CLOSE_WAIT"):
                port = conn.laddr.port
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                remote = None
                if conn.raddr:
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}"

                process_name = None
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                if port not in current_ports:
                    info = PortInfo(
                        port=port,
                        protocol=protocol,
                        pid=conn.pid,
                        process_name=process_name,
                        local_address=f"{conn.laddr.ip}:{port}",
                        remote_address=remote,
                        status=conn.status,
                    )
                    current_ports[port] = info

        return current_ports

    def get_changes(self, current: Dict[int, PortInfo]) -> dict:
        """
        Compare current scan with previous scan.
        Returns dict with 'new', 'closed', and 'unchanged' port lists.
        """
        prev_keys = set(self._previous_ports.keys())
        curr_keys = set(current.keys())

        new_ports = curr_keys - prev_keys
        closed_ports = prev_keys - curr_keys
        unchanged = curr_keys & prev_keys

        changes = {
            "new": [current[p] for p in new_ports],
            "closed": [self._previous_ports[p] for p in closed_ports],
            "unchanged": [current[p] for p in unchanged],
        }

        self._previous_ports = current
        return changes

    def get_listening_ports(self) -> List[PortInfo]:
        """Return only ports in LISTEN state (servers awaiting connections)."""
        ports = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN" and conn.laddr:
                    process_name = None
                    try:
                        if conn.pid:
                            process_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    ports.append(PortInfo(
                        port=conn.laddr.port,
                        protocol="TCP",
                        pid=conn.pid,
                        process_name=process_name,
                        local_address=f"{conn.laddr.ip}:{conn.laddr.port}",
                        status="LISTEN",
                    ))
        except psutil.AccessDenied:
            logger.warning("Access denied fetching listening ports.")
        return ports

    @property
    def previous_ports(self) -> Dict[int, PortInfo]:
        return self._previous_ports
