"""
PortGuard - Threat Detection Engine
Analyzes port activity and classifies threats.
"""

import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from dataclasses import dataclass, field

from core.port_scanner import PortInfo

logger = logging.getLogger("portguard.threat")

# Path to the malicious ports DB
MALICIOUS_DB_PATH = os.path.join(os.path.dirname(__file__), "malicious_ports.json")


@dataclass
class Threat:
    """Represents a detected security threat."""

    SEVERITY_INFO = "INFO"
    SEVERITY_LOW = "LOW"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"

    threat_id: str
    severity: str
    category: str
    description: str
    port: Optional[int] = None
    process: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "threat_id": self.threat_id,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "port": self.port,
            "process": self.process,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "extra": self.extra,
        }


class ThreatEngine:
    """
    Analyzes port scan results and detects various threat patterns.
    Maintains recent history for behavioral analysis.
    """

    def __init__(self):
        self._malicious_db = self._load_malicious_db()
        self._safe_ports = set(map(int, self._malicious_db.get("safe_ports", {}).keys()))
        self._threat_history: List[Threat] = []
        self._connection_tracker: Dict[str, List[datetime]] = defaultdict(list)
        self._port_open_times: Dict[int, datetime] = {}
        self._threat_counter = 0
        logger.info(f"ThreatEngine loaded {len(self._malicious_db.get('malicious_ports', {}))} malicious port signatures")

    def _load_malicious_db(self) -> dict:
        try:
            with open(MALICIOUS_DB_PATH, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load malicious ports DB: {e}")
            return {"malicious_ports": {}, "safe_ports": {}}

    def _next_id(self) -> str:
        self._threat_counter += 1
        return f"THR-{self._threat_counter:04d}"

    def analyze_port(self, port_info: PortInfo) -> List[Threat]:
        """Analyze a single port and return any threats found."""
        threats = []
        port_str = str(port_info.port)
        malicious = self._malicious_db.get("malicious_ports", {})

        # --- Rule 1: Malicious port match ---
        if port_str in malicious:
            entry = malicious[port_str]
            risk = entry.get("risk", "HIGH")
            threats.append(Threat(
                threat_id=self._next_id(),
                severity=risk,
                category="MALICIOUS_PORT",
                description=f"Port {port_info.port} matches known malicious signature: "
                            f"{entry['name']} — {entry['description']}",
                port=port_info.port,
                process=port_info.process_name,
                extra={"db_entry": entry},
            ))
            logger.warning(f"[THREAT] Malicious port {port_info.port} ({entry['name']}) — {risk}")

        # --- Rule 2: High-number ephemeral ports that shouldn't be listening ---
        elif port_info.port > 49152 and port_info.status == "LISTEN":
            threats.append(Threat(
                threat_id=self._next_id(),
                severity=Threat.SEVERITY_MEDIUM,
                category="SUSPICIOUS_EPHEMERAL_PORT",
                description=f"Port {port_info.port} is in the ephemeral range but is actively listening. "
                            f"This may indicate unauthorized service or backdoor.",
                port=port_info.port,
                process=port_info.process_name,
            ))
            logger.warning(f"[THREAT] Ephemeral port listening: {port_info.port}")

        # --- Rule 3: Unknown process on well-known port ---
        elif port_info.port < 1024 and port_info.process_name:
            expected_services = {
                80: ["nginx", "apache2", "httpd", "caddy", "python"],
                443: ["nginx", "apache2", "httpd", "caddy", "python"],
                22: ["sshd"],
                25: ["postfix", "sendmail", "exim"],
                53: ["named", "bind", "dnsmasq", "systemd-resolved"],
            }
            expected = expected_services.get(port_info.port)
            if expected and port_info.process_name.lower() not in expected:
                threats.append(Threat(
                    threat_id=self._next_id(),
                    severity=Threat.SEVERITY_HIGH,
                    category="UNEXPECTED_PROCESS",
                    description=f"Unexpected process '{port_info.process_name}' is listening on "
                                f"port {port_info.port}. Expected: {', '.join(expected)}.",
                    port=port_info.port,
                    process=port_info.process_name,
                ))
                logger.warning(f"[THREAT] Unexpected process on port {port_info.port}: {port_info.process_name}")

        if threats:
            self._threat_history.extend(threats)

        return threats

    def analyze_batch(self, ports: Dict[int, PortInfo]) -> List[Threat]:
        """Analyze all current ports and detect additional behavioral threats."""
        all_threats = []

        for port_info in ports.values():
            all_threats.extend(self.analyze_port(port_info))

        # --- Behavioral Rule: Port scan detection ---
        # If many ports opened rapidly (simulated via history growth)
        recent_threats = [
            t for t in self._threat_history
            if datetime.now() - t.timestamp < timedelta(minutes=1)
            and t.category == "MALICIOUS_PORT"
        ]
        if len(recent_threats) >= 3:
            all_threats.append(Threat(
                threat_id=self._next_id(),
                severity=Threat.SEVERITY_CRITICAL,
                category="PORT_SCAN_PATTERN",
                description=f"Possible port scan detected: {len(recent_threats)} malicious port triggers "
                            f"in the last 60 seconds.",
                extra={"trigger_count": len(recent_threats)},
            ))
            logger.critical("[THREAT] Port scan pattern detected!")

        return all_threats

    def get_threat_summary(self) -> dict:
        """Return aggregated threat statistics."""
        total = len(self._threat_history)
        by_severity = defaultdict(int)
        by_category = defaultdict(int)

        for t in self._threat_history:
            by_severity[t.severity] += 1
            by_category[t.category] += 1

        return {
            "total": total,
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
            "recent": [t.to_dict() for t in self._threat_history[-10:]],
        }

    @property
    def threat_history(self) -> List[Threat]:
        return list(self._threat_history)

    @property
    def malicious_port_list(self) -> dict:
        return self._malicious_db.get("malicious_ports", {})
