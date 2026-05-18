"""
PortGuard - Alert Notifier
Handles console, log, and optional email/desktop notifications for threats.
"""

import logging
import smtplib
import os
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

from detection.threat_engine import Threat

logger = logging.getLogger("portguard.notifier")

# ANSI color codes for terminal output
COLORS = {
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "RED":      "\033[91m",
    "YELLOW":   "\033[93m",
    "CYAN":     "\033[96m",
    "GREEN":    "\033[92m",
    "MAGENTA":  "\033[95m",
    "WHITE":    "\033[97m",
    "BG_RED":   "\033[41m",
    "BG_YELLOW":"\033[43m",
}

SEVERITY_COLORS = {
    "INFO":     COLORS["CYAN"],
    "LOW":      COLORS["GREEN"],
    "MEDIUM":   COLORS["YELLOW"],
    "HIGH":     COLORS["RED"],
    "CRITICAL": COLORS["BG_RED"] + COLORS["WHITE"] + COLORS["BOLD"],
}

SEVERITY_ICONS = {
    "INFO":     "ℹ️ ",
    "LOW":      "🔵",
    "MEDIUM":   "🟡",
    "HIGH":     "🔴",
    "CRITICAL": "🚨",
}


class Notifier:
    """
    Dispatches alerts via multiple channels:
    - Console (always on)
    - Logger (always on)
    - Email (optional, configure via environment)
    - Desktop notification (optional, Linux notify-send)
    """

    def __init__(self, email_config: Optional[dict] = None, desktop_notify: bool = True):
        self._email_config = email_config
        self._desktop_notify = desktop_notify
        self._alert_count = 0
        logger.info("Notifier initialized")
        if email_config:
            logger.info(f"Email alerts enabled → {email_config.get('to', 'N/A')}")
        if desktop_notify:
            logger.info("Desktop notifications enabled")

    def send_alert(self, threat: Threat):
        """Send alert for a detected threat through all configured channels."""
        self._alert_count += 1
        self._console_alert(threat)
        self._log_alert(threat)

        if self._email_config:
            self._email_alert(threat)

        if self._desktop_notify:
            self._desktop_alert(threat)

    def _console_alert(self, threat: Threat):
        """Print a formatted alert to the terminal."""
        color = SEVERITY_COLORS.get(threat.severity, COLORS["WHITE"])
        icon = SEVERITY_ICONS.get(threat.severity, "⚠️ ")
        reset = COLORS["RESET"]
        bold = COLORS["BOLD"]
        ts = threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        print(f"\n{'━' * 60}")
        print(f"{color}{bold}{icon} PORTGUARD ALERT [{threat.severity}]{reset}")
        print(f"  Time     : {ts}")
        print(f"  ID       : {threat.threat_id}")
        print(f"  Category : {threat.category}")
        if threat.port:
            print(f"  Port     : {threat.port}")
        if threat.process:
            print(f"  Process  : {threat.process}")
        print(f"  {color}{threat.description}{reset}")
        print(f"{'━' * 60}\n")

    def _log_alert(self, threat: Threat):
        """Write threat to the logger at appropriate level."""
        msg = (f"[{threat.threat_id}] [{threat.category}] "
               f"Port={threat.port} Process={threat.process} — {threat.description}")
        if threat.severity == "CRITICAL":
            logger.critical(msg)
        elif threat.severity == "HIGH":
            logger.error(msg)
        elif threat.severity == "MEDIUM":
            logger.warning(msg)
        else:
            logger.info(msg)

    def _email_alert(self, threat: Threat):
        """Send email notification (requires SMTP config)."""
        cfg = self._email_config
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[PortGuard] {threat.severity} Alert: {threat.category}"
            msg["From"] = cfg["from"]
            msg["To"] = cfg["to"]

            body = f"""
PortGuard Security Alert
========================
Severity : {threat.severity}
Category : {threat.category}
Time     : {threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")}
Port     : {threat.port or "N/A"}
Process  : {threat.process or "N/A"}

{threat.description}

-- PortGuard Security Monitor
            """
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(cfg["smtp_host"], cfg.get("smtp_port", 587)) as server:
                server.starttls()
                server.login(cfg["username"], cfg["password"])
                server.sendmail(cfg["from"], cfg["to"], msg.as_string())

            logger.info(f"Email alert sent for {threat.threat_id}")
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")

    def _desktop_alert(self, threat: Threat):
        """Send a desktop notification using notify-send (Linux)."""
        try:
            urgency = "low"
            if threat.severity in ("HIGH", "CRITICAL"):
                urgency = "critical"
            elif threat.severity == "MEDIUM":
                urgency = "normal"

            subprocess.run([
                "notify-send",
                "--urgency", urgency,
                "--app-name", "PortGuard",
                f"[{threat.severity}] {threat.category}",
                threat.description[:200],
            ], capture_output=True, timeout=3)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass  # notify-send not available — silently skip
        except Exception as e:
            logger.debug(f"Desktop notify error: {e}")

    def notify_port_opened(self, port: int, protocol: str, process: str = None):
        """Simple informational notice when a new port is detected."""
        proc_str = f" ({process})" if process else ""
        color = COLORS["CYAN"]
        reset = COLORS["RESET"]
        print(f"{color}[INFO]{reset} New port opened: {port}/{protocol}{proc_str}")

    def notify_port_closed(self, port: int, protocol: str):
        """Simple informational notice when a port is closed."""
        print(f"{COLORS['GREEN']}[INFO]{COLORS['RESET']} Port closed: {port}/{protocol}")

    @property
    def alert_count(self) -> int:
        return self._alert_count
