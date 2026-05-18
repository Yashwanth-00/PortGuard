"""
PortGuard — Main Entry Point
Starts monitoring engine, threat detection, and optionally the dashboard.
"""

import logging
import os
import sys
import time
import signal
import argparse
from datetime import datetime

# ── Logging setup ────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("logs/portguard.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger("portguard")

# ── Module imports ────────────────────────────────────────────────────────────
from core.monitor_engine import MonitorEngine, MonitorEvent
from core.port_scanner import PortInfo
from detection.threat_engine import ThreatEngine, Threat
from alerts.notifier import Notifier


# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════╗
║                                                      ║
║    ██████╗  ██████╗ ██████╗ ████████╗               ║
║    ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝               ║
║    ██████╔╝██║   ██║██████╔╝   ██║                  ║
║    ██╔═══╝ ██║   ██║██╔══██╗   ██║                  ║
║    ██║     ╚██████╔╝██║  ██║   ██║                  ║
║    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝                  ║
║                                                      ║
║    ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗         ║
║   ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗        ║
║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║        ║
║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║        ║
║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝        ║
║    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝         ║
║                                                      ║
║   Host-Based Network Security Monitor v1.0           ║
║   github.com/yourname/portguard                      ║
╚══════════════════════════════════════════════════════╝
"""


def build_event_handler(threat_engine: ThreatEngine, notifier: Notifier,
                         monitor_engine: MonitorEngine):
    """Build and return the event handler closure."""

    def handle_event(event: MonitorEvent):
        if event.event_type == MonitorEvent.EVENT_PORT_OPENED:
            port_info: PortInfo = event.port_info
            notifier.notify_port_opened(
                port_info.port, port_info.protocol, port_info.process_name
            )
            # Run threat analysis on newly opened port
            threats = threat_engine.analyze_port(port_info)
            for threat in threats:
                monitor_engine.increment_threat_count()
                notifier.send_alert(threat)

        elif event.event_type == MonitorEvent.EVENT_PORT_CLOSED:
            port_info: PortInfo = event.port_info
            notifier.notify_port_closed(port_info.port, port_info.protocol)

        elif event.event_type == MonitorEvent.EVENT_SCAN_COMPLETE:
            logger.debug(event.message)

    return handle_event


def run_cli(args):
    """Run PortGuard in CLI-only monitoring mode."""
    print(BANNER)
    logger.info("PortGuard starting — CLI mode")
    logger.info(f"Scan interval: {args.interval}s | Dashboard: {'enabled' if args.dashboard else 'disabled'}")

    threat_engine = ThreatEngine()
    notifier = Notifier(desktop_notify=not args.no_desktop)
    monitor = MonitorEngine(scan_interval=args.interval)

    monitor.register_listener(build_event_handler(threat_engine, notifier, monitor))

    # Initial batch analysis of already-open ports
    logger.info("Running initial port baseline scan...")
    initial_ports = monitor._scanner.scan()
    logger.info(f"Baseline: {len(initial_ports)} ports found. Running threat analysis...")
    initial_threats = threat_engine.analyze_batch(initial_ports)
    for threat in initial_threats:
        monitor.increment_threat_count()
        notifier.send_alert(threat)

    monitor.start()

    # Optionally start dashboard
    if args.dashboard:
        from dashboard.app import app as flask_app, init_dashboard
        import threading
        init_dashboard(monitor, threat_engine, notifier)
        dash_thread = threading.Thread(
            target=lambda: flask_app.run(
                host="0.0.0.0", port=args.port, debug=False, use_reloader=False
            ),
            daemon=True,
            name="DashboardThread"
        )
        dash_thread.start()
        logger.info(f"Dashboard available at http://localhost:{args.port}")

    # Handle graceful shutdown
    def shutdown(sig, frame):
        print("\n")
        logger.info("Shutdown signal received. Stopping PortGuard...")
        monitor.stop()
        summary = threat_engine.get_threat_summary()
        logger.info(f"Session summary — Threats detected: {summary['total']}")
        logger.info(f"By severity: {summary['by_severity']}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("PortGuard is running. Press Ctrl+C to stop.")

    # Keep main thread alive
    while True:
        time.sleep(30)
        stats = monitor.stats
        logger.info(
            f"[STATUS] Uptime={monitor.uptime} | Scans={stats['scans_performed']} | "
            f"Threats={stats['threats_detected']} | Alerts={notifier.alert_count}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="PortGuard — Host-Based Network Security Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                        # Monitor with defaults
  python main.py --dashboard            # Monitor + web dashboard
  python main.py --interval 10          # Scan every 10 seconds
  python main.py --dashboard --port 8080  # Dashboard on port 8080
        """
    )
    parser.add_argument("--interval",    type=int, default=5,    help="Scan interval in seconds (default: 5)")
    parser.add_argument("--dashboard",   action="store_true",     help="Start web dashboard")
    parser.add_argument("--port",        type=int, default=5000,  help="Dashboard port (default: 5000)")
    parser.add_argument("--no-desktop",  action="store_true",     help="Disable desktop notifications")

    args = parser.parse_args()
    run_cli(args)


if __name__ == "__main__":
    main()
