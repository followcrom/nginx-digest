#!/usr/bin/env python3
"""
Nginx Analytics Daily Digest
============================
Parses nginx access logs, generates visitor analytics, gets LLM commentary,
and sends a daily email digest.
"""
from __future__ import annotations

import re
import sys
import gzip
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import NamedTuple, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load environment variables from .env file
import os
from dotenv import load_dotenv
from pathlib import Path

# Load .env from the same directory as this script
env_path = Path(__file__).parent / '.env'
load_dotenv(env_path)

LOG_FILE = "nginx_digest.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()  # Only output to console (bash script handles file logging)
    ]
)
logger = logging.getLogger(__name__)

# Only show WARNING or higher messages from the llm library
logging.getLogger("llm").setLevel(logging.WARNING)

# Use a project-specific LLM configuration directory
os.environ["LLM_USER_PATH"] = ".llm"

import llm

# Optional imports - graceful degradation if not available
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logger.warning("geoip2 not installed. Location data will be unavailable.")

try:
    from user_agents import parse as parse_user_agent
    USER_AGENTS_AVAILABLE = True
except ImportError:
    USER_AGENTS_AVAILABLE = False
    logger.warning("user-agents not installed. Detailed UA parsing will be unavailable.")


# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG = {
    # Nginx log location (supports glob patterns)
    "log_path": "/var/log/nginx/access.log",

    # GeoIP database path (download from MaxMind)
    "geoip_db_path": "/var/lib/GeoIP/GeoLite2-City.mmdb",

    # Email settings (can be overridden by environment variables)
    "email_to": os.getenv("EMAIL_TO"),

    # LLM settings (using the llm library)
    "llm_model": "deepseek-chat",

    # Used in build_sessions() to decide when to create a new session vs. continuing an existing one
    "session_timeout_minutes": 30,
}

# Known probe/attack patterns to filter from top pages
PROBE_PATTERNS = [
    '.env', 'wp-', 'admin.php', 'xmlrpc', '.php',
    'phpmyadmin', 'mysql', 'wp-login', 'wp-admin',
    '.git', '.aws', 'config.', 'backup', '.sql',
    'shell', 'eval-stdin', 'vendor/', 'owa/auth',
    'solr/', 'console/', 'manager/', 'api/jsonws',
    'cgi-bin', 'jenkins', 'actuator', 'telescope',
    '.aspx', '.asp', 'admin/', 'administrator/',
]

# Security alert thresholds
ALERT_THRESHOLDS = {
    "suspicious_requests": 100,        # Alert if >100 suspicious requests/day
    "bot_session_percentage": 80,      # Alert if >80% of sessions are bots
    "single_ip_requests": 200,         # Alert if single IP makes >200 requests
    "failed_requests_percentage": 20,  # Alert if >20% requests are 4xx/5xx
    "suspicious_spike": 50,            # Alert if one suspicious pattern >50 hits
}


# =============================================================================
# DATA STRUCTURES
# =============================================================================

class LogEntry(NamedTuple):
    """Parsed nginx log entry"""
    ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    size: int
    referer: str
    user_agent: str
    host: str


class VisitorSession:
    """Represents a visitor session"""
    def __init__(self, ip: str, first_seen: datetime):
        self.ip = ip
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.pages: list[str] = []
        self.total_bytes = 0
        self.requests = 0
        self.static_requests = 0  # CSS, JS, images, fonts
        self.user_agents: list[str] = []
        self.accessed_technical_endpoints = False
        self.is_bot = False  # Will be determined by behavioral analysis

    @property
    def duration_seconds(self) -> int:
        return int((self.last_seen - self.first_seen).total_seconds())

    @property
    def requests_per_minute(self) -> float:
        """Average requests per minute"""
        if self.duration_seconds < 60:
            return self.requests  # Less than a minute, count total
        return (self.requests / self.duration_seconds) * 60

    @property
    def static_resource_ratio(self) -> float:
        """Ratio of static resources to total requests"""
        if self.requests == 0:
            return 0.0
        return self.static_requests / self.requests

    def add_request(self, entry: LogEntry):
        self.last_seen = entry.timestamp
        if entry.path not in self.pages:
            self.pages.append(entry.path)
        self.total_bytes += entry.size
        self.requests += 1

        # Track static resources
        if self._is_static_resource(entry.path):
            self.static_requests += 1

        # Track user agents
        if entry.user_agent not in self.user_agents:
            self.user_agents.append(entry.user_agent)

        # Check for technical endpoint access
        if self._is_technical_endpoint(entry.path):
            self.accessed_technical_endpoints = True

    @staticmethod
    def _is_static_resource(path: str) -> bool:
        """Check if path is a static resource"""
        static_extensions = ['.css', '.js', '.jpg', '.jpeg', '.png', '.gif',
                           '.webp', '.svg', '.ico', '.woff', '.woff2', '.ttf',
                           '.eot', '.mp4', '.webm', '.pdf']
        return any(path.lower().endswith(ext) for ext in static_extensions)

    @staticmethod
    def _is_technical_endpoint(path: str) -> bool:
        """Check if path is a technical/crawler endpoint"""
        technical_paths = ['robots.txt', 'sitemap.xml', '.well-known/',
                          'ads.txt', 'security.txt', 'humans.txt']
        return any(tp in path.lower() for tp in technical_paths)


# =============================================================================
# LOG PARSING
# =============================================================================

# Combined nginx log format regex
# Handles: '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_host"'
# Also handles logs without host at the end
NGINX_LOG_PATTERN = re.compile(
    r'(?P<ip>[\d.:a-fA-F]+)\s+-\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
    r'(?:\s+"(?P<host>[^"]*)")?'
)


def parse_timestamp(ts_str: str) -> datetime:
    """Parse nginx timestamp format: 24/Dec/2024:10:15:30 +0000"""
    # Remove timezone for simpler parsing
    ts_clean = ts_str.split()[0] if ' ' in ts_str else ts_str
    return datetime.strptime(ts_clean, "%d/%b/%Y:%H:%M:%S")


def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parse a single nginx log line"""
    match = NGINX_LOG_PATTERN.match(line)
    if not match:
        return None
    
    try:
        return LogEntry(
            ip=match.group("ip"),
            timestamp=parse_timestamp(match.group("timestamp")),
            method=match.group("method"),
            path=match.group("path"),
            status=int(match.group("status")),
            size=int(match.group("size")),
            referer=match.group("referer") or "-",
            user_agent=match.group("user_agent") or "-",
            host=match.group("host") or "-",
        )
    except (ValueError, AttributeError):
        return None


def read_log_file(log_path: str, target_date: datetime.date) -> list[LogEntry]:
    """Read and parse log file, filtering for target date"""
    entries = []
    path = Path(log_path)
    
    # Also check for rotated logs (.1, .gz)
    log_files = [path]
    if path.with_suffix('.log.1').exists():
        log_files.append(path.with_suffix('.log.1'))
    
    # Check for gzipped rotated logs
    for gz_path in path.parent.glob(f"{path.stem}*.gz"):
        log_files.append(gz_path)
    
    for log_file in log_files:
        try:
            if str(log_file).endswith('.gz'):
                opener = gzip.open(log_file, 'rt', encoding='utf-8', errors='replace')
            else:
                opener = open(log_file, 'r', encoding='utf-8', errors='replace')
            
            with opener as f:
                for line in f:
                    entry = parse_log_line(line.strip())
                    if entry and entry.timestamp.date() == target_date:
                        entries.append(entry)
        except (IOError, OSError) as e:
            logger.warning(f"Could not read {log_file}: {e}")
    
    return sorted(entries, key=lambda e: e.timestamp)


# =============================================================================
# ANALYTICS
# =============================================================================

def build_sessions(entries: list[LogEntry]) -> dict[str, list[VisitorSession]]:
    """Group log entries into visitor sessions"""
    sessions_by_ip: dict[str, list[VisitorSession]] = defaultdict(list)
    timeout = timedelta(minutes=CONFIG["session_timeout_minutes"])
    
    for entry in entries:
        ip_sessions = sessions_by_ip[entry.ip]
        
        # Check if this belongs to the current session or starts a new one
        if ip_sessions and (entry.timestamp - ip_sessions[-1].last_seen) < timeout:
            ip_sessions[-1].add_request(entry)
        else:
            new_session = VisitorSession(entry.ip, entry.timestamp)
            new_session.add_request(entry)
            ip_sessions.append(new_session)
    
    return sessions_by_ip


def get_location(ip: str, geoip_reader) -> dict:
    """Get location info for an IP address"""
    if not geoip_reader:
        return {"country": "Unknown", "city": "Unknown", "region": "Unknown"}
    
    try:
        response = geoip_reader.city(ip)
        return {
            "country": response.country.name or "Unknown",
            "city": response.city.name or "Unknown",
            "region": response.subdivisions.most_specific.name if response.subdivisions else "Unknown",
        }
    except Exception:
        return {"country": "Unknown", "city": "Unknown", "region": "Unknown"}


def analyze_bot_behavior(session: VisitorSession) -> tuple[bool, list[str]]:
    """
    Analyze session behavior to determine if it's likely a bot.
    Returns (is_bot, reasons)
    """
    reasons = []

    # 1. High request rate (>12 requests/min sustained)
    if session.requests_per_minute > 12 and session.requests > 10:
        reasons.append("high_request_rate")

    # 2. No static resources (real browsers always load CSS/JS/images)
    if session.requests > 5 and session.static_resource_ratio < 0.1:
        reasons.append("no_static_resources")

    # 3. Excessive page depth (bots crawl systematically)
    if len(session.pages) > 30:
        reasons.append("excessive_page_depth")

    # 4. Very high page-to-request ratio (only fetching HTML, no assets)
    if session.requests > 5:
        page_ratio = len(session.pages) / session.requests
        if page_ratio > 0.9:  # >90% of requests are unique pages
            reasons.append("high_page_ratio")

    # 5. Technical endpoint access combined with other signals
    if session.accessed_technical_endpoints and len(reasons) > 0:
        reasons.append("technical_endpoint_access")

    # 6. Suspiciously consistent timing (perfect intervals)
    if session.duration_seconds > 120 and session.requests > 10:
        avg_interval = session.duration_seconds / session.requests
        # Very consistent intervals (5-15 seconds perfectly) suggests automation
        if 5 <= avg_interval <= 15:
            reasons.append("consistent_timing")

    # 7. Multiple user agents in one session (session hijacking or bot rotation)
    if len(session.user_agents) > 2:
        reasons.append("multiple_user_agents")

    # Decision: Bot if 2+ behavioral red flags
    is_bot = len(reasons) >= 2

    return is_bot, reasons


def parse_device_info(user_agent: str) -> dict:
    """Parse user agent string for detailed device, browser, and OS information"""

    if USER_AGENTS_AVAILABLE:
        # Use user-agents library for detailed parsing
        ua = parse_user_agent(user_agent)

        # Device type
        if ua.is_mobile:
            device = "Mobile"
        elif ua.is_tablet:
            device = "Tablet"
        elif ua.is_pc:
            device = "Desktop"
        else:
            device = "Unknown"

        # Browser with version
        browser_family = ua.browser.family if ua.browser.family else "Unknown"
        browser_version = ua.browser.version_string if ua.browser.version_string else ""

        # For display, use family + major.minor version (not full version to reduce clutter)
        if browser_version:
            # Get major.minor version (e.g., "120.0" from "120.0.6099.129")
            version_parts = browser_version.split('.')
            short_version = '.'.join(version_parts[:2]) if len(version_parts) >= 2 else version_parts[0]
            browser_display = f"{browser_family} {short_version}"
        else:
            browser_display = browser_family

        # OS with version
        os_family = ua.os.family if ua.os.family else "Unknown"
        os_version = ua.os.version_string if ua.os.version_string else ""

        if os_version:
            os_display = f"{os_family} {os_version}"
        else:
            os_display = os_family

        return {
            "browser": browser_display,
            "browser_family": browser_family,
            "os": os_display,
            "os_family": os_family,
            "device": device,
            "is_bot": ua.is_bot,
        }

    else:
        # Fallback to basic string matching if user-agents not available
        device = "Desktop"
        if "Mobile" in user_agent or "Android" in user_agent:
            device = "Mobile"
        elif "iPad" in user_agent or "Tablet" in user_agent:
            device = "Tablet"

        browser = "Unknown"
        if "Chrome" in user_agent:
            browser = "Chrome"
        elif "Firefox" in user_agent:
            browser = "Firefox"
        elif "Safari" in user_agent:
            browser = "Safari"
        elif "Edge" in user_agent:
            browser = "Edge"

        is_bot = any(bot_keyword in user_agent.lower() for bot_keyword in ["bot", "crawler", "spider", "curl", "wget", "python-requests", "go-http-client", "headlesschrome"])

        return {
            "browser": browser,
            "browser_family": browser,
            "os": "Unknown",
            "os_family": "Unknown",
            "device": device,
            "is_bot": is_bot,
        }


def detect_anomalies(analytics: dict, sessions_by_ip: dict) -> list[dict]:
    """
    Detect anomalous activity patterns and generate alerts.
    Returns list of alert dictionaries with severity and description.
    """
    alerts = []
    s = analytics["summary"]

    # 1. High volume of suspicious requests
    if s["suspicious_requests"] > ALERT_THRESHOLDS["suspicious_requests"]:
        alerts.append({
            "severity": "HIGH",
            "type": "suspicious_volume",
            "message": f"{s['suspicious_requests']} suspicious/probe requests detected (threshold: {ALERT_THRESHOLDS['suspicious_requests']})",
            "details": f"Top patterns: {', '.join(list(analytics['suspicious_requests'].keys())[:3])}"
        })

    # 2. Bot traffic dominance
    if s["total_sessions"] > 0:
        bot_percentage = (s["bot_sessions"] / s["total_sessions"]) * 100
        if bot_percentage > ALERT_THRESHOLDS["bot_session_percentage"]:
            alerts.append({
                "severity": "MEDIUM",
                "type": "bot_dominance",
                "message": f"{bot_percentage:.1f}% of sessions are bots (threshold: {ALERT_THRESHOLDS['bot_session_percentage']}%)",
                "details": f"Bot sessions: {s['bot_sessions']}, Human sessions: {s['human_sessions']}"
            })

    # 3. Single IP making excessive requests
    max_requests_per_ip = 0
    worst_offender_ip = None
    for ip, sessions in sessions_by_ip.items():
        total_requests = sum(session.requests for session in sessions)
        if total_requests > max_requests_per_ip:
            max_requests_per_ip = total_requests
            worst_offender_ip = ip

    if max_requests_per_ip > ALERT_THRESHOLDS["single_ip_requests"]:
        alerts.append({
            "severity": "HIGH",
            "type": "single_ip_abuse",
            "message": f"IP {worst_offender_ip} made {max_requests_per_ip} requests (threshold: {ALERT_THRESHOLDS['single_ip_requests']})",
            "details": f"Consider blocking or rate-limiting this IP"
        })

    # 4. High error rate
    total_status_codes = sum(analytics["status_codes"].values())
    error_codes = sum(count for status, count in analytics["status_codes"].items()
                      if status >= 400)
    if total_status_codes > 0:
        error_percentage = (error_codes / total_status_codes) * 100
        if error_percentage > ALERT_THRESHOLDS["failed_requests_percentage"]:
            alerts.append({
                "severity": "MEDIUM",
                "type": "high_error_rate",
                "message": f"{error_percentage:.1f}% of requests failed (threshold: {ALERT_THRESHOLDS['failed_requests_percentage']}%)",
                "details": f"Total errors: {error_codes} out of {total_status_codes} requests"
            })

    # 5. Spike in specific attack pattern
    for pattern, count in analytics["suspicious_requests"].items():
        if count > ALERT_THRESHOLDS["suspicious_spike"]:
            alerts.append({
                "severity": "HIGH",
                "type": "attack_pattern_spike",
                "message": f"Spike detected: '{pattern}' accessed {count} times (threshold: {ALERT_THRESHOLDS['suspicious_spike']})",
                "details": "This could indicate an active attack or aggressive scanning"
            })

    # 6. Unusual status codes (502, 503 suggesting server issues or DDoS)
    server_errors = sum(count for status, count in analytics["status_codes"].items()
                       if status >= 500)
    if server_errors > 50:
        alerts.append({
            "severity": "HIGH",
            "type": "server_errors",
            "message": f"{server_errors} server errors (5xx) detected",
            "details": "Could indicate server overload, misconfiguration, or DDoS attempt"
        })

    # 7. New/unknown attack patterns (paths not in PROBE_PATTERNS but highly suspicious)
    for path, count in list(analytics["suspicious_requests"].items())[:5]:
        if count > 20 and not any(pattern in path.lower() for pattern in PROBE_PATTERNS[:5]):
            # This is a new pattern we haven't seen before
            alerts.append({
                "severity": "MEDIUM",
                "type": "new_attack_pattern",
                "message": f"New suspicious pattern detected: '{path}' ({count} attempts)",
                "details": "Consider adding to PROBE_PATTERNS or blocking in nginx"
            })
            break  # Only alert on the most frequent new pattern

    return alerts


def generate_analytics(entries: list[LogEntry], target_date: datetime.date) -> dict:
    """Generate comprehensive analytics from log entries"""

    # Initialize GeoIP reader
    geoip_reader = None
    if GEOIP_AVAILABLE and Path(CONFIG["geoip_db_path"]).exists():
        try:
            geoip_reader = geoip2.database.Reader(CONFIG["geoip_db_path"])
        except Exception as e:
            logger.warning(f"Could not load GeoIP database: {e}")
    
    # Build sessions
    sessions_by_ip = build_sessions(entries)
    all_sessions = [s for sessions in sessions_by_ip.values() for s in sessions]

    # Analyze bot behavior for each session
    bot_behavior_reasons = Counter()
    for session in all_sessions:
        is_bot, reasons = analyze_bot_behavior(session)
        session.is_bot = is_bot
        if is_bot:
            for reason in reasons:
                bot_behavior_reasons[reason] += 1

    # Separate human and bot sessions
    human_sessions = [s for s in all_sessions if not s.is_bot]
    bot_sessions = [s for s in all_sessions if s.is_bot]

    # Collect stats
    unique_visitors = len(sessions_by_ip)
    total_sessions = len(all_sessions)
    total_pageviews = sum(s.requests for s in all_sessions)
    total_bandwidth = sum(s.total_bytes for s in all_sessions)

    # Human-only stats (for more accurate engagement metrics)
    human_pageviews = sum(s.requests for s in human_sessions)
    bot_pageviews = sum(s.requests for s in bot_sessions)
    
    # Location breakdown
    locations = Counter()
    countries = Counter()
    for ip in sessions_by_ip.keys():
        loc = get_location(ip, geoip_reader)
        locations[f"{loc['city']}, {loc['country']}"] += 1
        countries[loc['country']] += 1
    
    # Page popularity and suspicious request detection
    page_views = Counter()
    suspicious_requests = Counter()

    def is_suspicious(path: str) -> bool:
        """Check if a path matches known probe patterns"""
        path_lower = path.lower()
        return any(pattern in path_lower for pattern in PROBE_PATTERNS)

    for entry in entries:
        # Normalize paths (remove query strings for grouping)
        clean_path = entry.path.split('?')[0]

        if is_suspicious(clean_path):
            suspicious_requests[clean_path] += 1
        else:
            page_views[clean_path] += 1
    
    # Device breakdown and bot detection
    devices = Counter()
    browsers = Counter()  # Detailed browser versions
    browser_families = Counter()  # Browser families for summary
    operating_systems = Counter()  # Detailed OS versions
    os_families = Counter()  # OS families for summary
    bot_traffic = 0
    human_traffic = 0
    bot_details = Counter()  # Track which bots are visiting

    for entry in entries:
        device_info = parse_device_info(entry.user_agent)

        if device_info["is_bot"]:
            bot_traffic += 1
            # Extract bot name from user agent
            ua_lower = entry.user_agent.lower()
            if "googlebot" in ua_lower:
                bot_details["Googlebot"] += 1
            elif "bingbot" in ua_lower:
                bot_details["Bingbot"] += 1
            elif "yandex" in ua_lower:
                bot_details["YandexBot"] += 1
            elif "baiduspider" in ua_lower:
                bot_details["Baiduspider"] += 1
            elif "facebookexternalhit" in ua_lower:
                bot_details["Facebook Bot"] += 1
            elif "twitterbot" in ua_lower:
                bot_details["Twitter Bot"] += 1
            elif "slackbot" in ua_lower:
                bot_details["Slackbot"] += 1
            elif "linkedinbot" in ua_lower:
                bot_details["LinkedInBot"] += 1
            else:
                bot_details["Other Bots"] += 1
        else:
            human_traffic += 1
            devices[device_info["device"]] += 1
            browsers[device_info["browser"]] += 1
            browser_families[device_info["browser_family"]] += 1
            operating_systems[device_info["os"]] += 1
            os_families[device_info["os_family"]] += 1
    
    # Referrers (external only)
    referrers = Counter()
    for entry in entries:
        if entry.referer and entry.referer != "-":
            # Extract domain from referrer
            try:
                from urllib.parse import urlparse
                ref_domain = urlparse(entry.referer).netloc
                if ref_domain:
                    referrers[ref_domain] += 1
            except Exception:
                pass
    
    # Traffic by hour
    hourly_traffic = Counter()
    for entry in entries:
        hourly_traffic[entry.timestamp.hour] += 1
    
    # Session duration stats (human sessions only for realistic averages)
    human_durations = [s.duration_seconds for s in human_sessions]
    avg_duration = sum(human_durations) / len(human_durations) if human_durations else 0

    # Pages per session (human sessions only)
    human_pages_per_session = [len(s.pages) for s in human_sessions]
    avg_pages = sum(human_pages_per_session) / len(human_pages_per_session) if human_pages_per_session else 0
    
    # Service breakdown (by host)
    service_stats = Counter()
    for entry in entries:
        service_stats[entry.host] += 1
    
    # Status code breakdown
    status_codes = Counter()
    for entry in entries:
        status_codes[entry.status] += 1
    
    # Close GeoIP reader
    if geoip_reader:
        geoip_reader.close()

    analytics = {
        "date": target_date.isoformat(),
        "summary": {
            "unique_visitors": unique_visitors,
            "total_sessions": total_sessions,
            "human_sessions": len(human_sessions),
            "bot_sessions": len(bot_sessions),
            "total_pageviews": total_pageviews,
            "human_pageviews": human_pageviews,
            "bot_pageviews": bot_pageviews,
            "total_bandwidth_mb": round(total_bandwidth / (1024 * 1024), 2),
            "avg_session_duration_seconds": round(avg_duration),
            "avg_pages_per_session": round(avg_pages, 1),
            "human_traffic": human_traffic,
            "bot_traffic": bot_traffic,
            "suspicious_requests": sum(suspicious_requests.values()),
        },
        "bot_behavior_reasons": dict(bot_behavior_reasons.most_common()),
        "top_pages": dict(page_views.most_common(15)),
        "suspicious_requests": dict(suspicious_requests.most_common(15)),
        "top_locations": dict(locations.most_common(10)),
        "countries": dict(countries.most_common(10)),
        "devices": dict(devices),
        "browsers": dict(browsers.most_common(10)),
        "browser_families": dict(browser_families.most_common(8)),
        "operating_systems": dict(operating_systems.most_common(10)),
        "os_families": dict(os_families.most_common(8)),
        "referrers": dict(referrers.most_common(10)),
        "hourly_traffic": dict(sorted(hourly_traffic.items())),
        "services": dict(service_stats.most_common(10)),
        "status_codes": dict(status_codes),
        "bot_details": dict(bot_details.most_common(10)),
    }

    # Detect anomalies and add alerts
    alerts = detect_anomalies(analytics, sessions_by_ip)
    analytics["security_alerts"] = alerts

    return analytics


# =============================================================================
# REPORT GENERATION
# =============================================================================

def format_duration(seconds: int) -> str:
    """Format seconds into human-readable duration"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"


def generate_text_report(analytics: dict) -> str:
    """Generate a human-readable text report"""
    s = analytics["summary"]

    # Security alerts section (if any)
    alerts_section = ""
    if analytics.get("security_alerts"):
        alerts_section = """
╔═══════════════════════════════════════════════════════════════════╗
║                      SECURITY ALERTS                              ║
╚═══════════════════════════════════════════════════════════════════╝
"""
        for alert in analytics["security_alerts"]:
            severity_symbol = "🔴" if alert["severity"] == "HIGH" else "🟡"
            alerts_section += f"\n[{alert['severity']}] {severity_symbol} {alert['type'].upper()}\n"
            alerts_section += f"  {alert['message']}\n"
            alerts_section += f"  → {alert['details']}\n"

        alerts_section += "\n"

    report = f"""
═══════════════════════════════════════════════════════════════════
               NGINX ANALYTICS DIGEST - {analytics['date']}
═══════════════════════════════════════════════════════════════════
{alerts_section}
SUMMARY
───────────────────────────────────────────────────────────────────
  • Unique Visitors:     {s['unique_visitors']:,}
  • Total Sessions:      {s['total_sessions']:,}
  • Human Sessions:      {s['human_sessions']:,} ({s['human_sessions']/s['total_sessions']*100:.1f}%)
  • Bot Sessions:        {s['bot_sessions']:,} ({s['bot_sessions']/s['total_sessions']*100:.1f}%)

  • Total Pageviews:     {s['total_pageviews']:,}
  • Human Pageviews:     {s['human_pageviews']:,} ({s['human_pageviews']/s['total_pageviews']*100:.1f}%)
  • Bot Pageviews:       {s['bot_pageviews']:,} ({s['bot_pageviews']/s['total_pageviews']*100:.1f}%)
  • Suspicious Requests: {s['suspicious_requests']:,}

  • Bandwidth Used:      {s['total_bandwidth_mb']:.2f} MB
  • Avg Session Length:  {format_duration(s['avg_session_duration_seconds'])} (human sessions)
  • Avg Pages/Session:   {s['avg_pages_per_session']} (human sessions)

TOP PAGES (Legitimate Traffic)
───────────────────────────────────────────────────────────────────
"""
    for page, count in list(analytics["top_pages"].items())[:10]:
        report += f"  {count:>5}  {page}\n"

    if analytics["suspicious_requests"]:
        report += """
SUSPICIOUS REQUESTS (Probes/Attacks)
───────────────────────────────────────────────────────────────────
"""
        for page, count in list(analytics["suspicious_requests"].items())[:15]:
            report += f"  {count:>5}  {page}\n"

    if analytics["countries"]:
        report += """
VISITOR COUNTRIES
───────────────────────────────────────────────────────────────────
"""
        for location, count in analytics["countries"].items():
            report += f"  {count:>5}  {location}\n"
    
    if analytics["top_locations"]:
        report += """
TOP CITIES
───────────────────────────────────────────────────────────────────
"""
        for location, count in list(analytics["top_locations"].items())[:8]:
            report += f"  {count:>5}  {location}\n"
    
    if analytics["devices"]:
        report += """
DEVICES
───────────────────────────────────────────────────────────────────
"""
        for device, count in analytics["devices"].items():
            pct = (count / s["total_pageviews"] * 100) if s["total_pageviews"] else 0
            report += f"  {device:<12} {count:>5} ({pct:.1f}%)\n"
    
    if analytics["browsers"]:
        report += """
BROWSER VERSIONS (Top 10)
───────────────────────────────────────────────────────────────────
"""
        for browser, count in list(analytics["browsers"].items())[:10]:
            report += f"  {count:>5}  {browser}\n"

    if analytics["browser_families"]:
        report += """
BROWSER FAMILIES
───────────────────────────────────────────────────────────────────
"""
        for browser, count in list(analytics["browser_families"].items())[:8]:
            pct = (count / s["human_traffic"] * 100) if s["human_traffic"] else 0
            report += f"  {browser:<20} {count:>5} ({pct:.1f}%)\n"

    if analytics["operating_systems"]:
        report += """
OPERATING SYSTEMS (Top 10)
───────────────────────────────────────────────────────────────────
"""
        for os_name, count in list(analytics["operating_systems"].items())[:10]:
            report += f"  {count:>5}  {os_name}\n"

    if analytics["os_families"]:
        report += """
OS FAMILIES
───────────────────────────────────────────────────────────────────
"""
        for os_name, count in list(analytics["os_families"].items())[:8]:
            pct = (count / s["human_traffic"] * 100) if s["human_traffic"] else 0
            report += f"  {os_name:<20} {count:>5} ({pct:.1f}%)\n"
    
    if analytics["referrers"]:
        report += """
TOP REFERRERS
───────────────────────────────────────────────────────────────────
"""
        for referrer, count in list(analytics["referrers"].items())[:8]:
            report += f"  {count:>5}  {referrer}\n"
    
    if analytics["services"]:
        report += """
TRAFFIC BY SERVICE/HOST
───────────────────────────────────────────────────────────────────
"""
        for service, count in analytics["services"].items():
            report += f"  {count:>5}  {service}\n"

    if analytics["bot_details"]:
        report += """
BOT ACTIVITY (by User Agent)
───────────────────────────────────────────────────────────────────
"""
        for bot_name, count in analytics["bot_details"].items():
            report += f"  {count:>5}  {bot_name}\n"

    if analytics["bot_behavior_reasons"]:
        report += """
BOT DETECTION REASONS (Behavioral Analysis)
───────────────────────────────────────────────────────────────────
"""
        reason_labels = {
            "high_request_rate": "High request rate (>12/min)",
            "no_static_resources": "No static resources loaded",
            "excessive_page_depth": "Excessive pages crawled (>30)",
            "high_page_ratio": "Only fetching HTML (no assets)",
            "technical_endpoint_access": "Accessed robots.txt/sitemap",
            "consistent_timing": "Perfectly timed requests",
            "multiple_user_agents": "Multiple user agents",
        }
        for reason, count in analytics["bot_behavior_reasons"].items():
            label = reason_labels.get(reason, reason)
            report += f"  {count:>5}  {label}\n"

    # Hourly traffic sparkline (simple text visualization)
    if analytics["hourly_traffic"]:
        report += """
HOURLY TRAFFIC
───────────────────────────────────────────────────────────────────
"""
        max_hourly = max(analytics["hourly_traffic"].values()) if analytics["hourly_traffic"] else 1
        for hour in range(24):
            count = analytics["hourly_traffic"].get(hour, 0)
            bar_len = int((count / max_hourly) * 30) if max_hourly else 0
            bar = "█" * bar_len
            report += f"  {hour:02d}:00  {bar} {count}\n"
    
    report += "\n═══════════════════════════════════════════════════════════════════\n"
    
    return report


# =============================================================================
# LLM ANALYSIS
# =============================================================================

def get_llm_analysis(report: str) -> str:
    """Get LLM commentary on the analytics using the llm Python SDK"""

    prompt = f"""You are analyzing website traffic analytics for Teed's developer portfolio.
Here is today's analytics data:

{report}

Please provide a brief, insightful analysis covering:
1. Overall traffic health and any notable patterns
2. Geographic distribution insights
3. Most interesting pages/content based on popularity
4. Any actionable recommendations
5. Anything unusual or noteworthy

Keep the tone conversational and helpful, as if you're a colleague reviewing the stats with me.
If there has been no significant traffic or data, feel free to make a light-hearted comment about the lack of visitors!"""

    try:
        # Get the model instance
        model = llm.get_model(CONFIG["llm_model"])

        # Generate response
        response = model.prompt(prompt)

        if response and response.text():
            return response.text().strip()
        else:
            return "[LLM analysis unavailable: empty response]"

    except llm.UnknownModelError:
        return f"[LLM analysis error: model '{CONFIG['llm_model']}' not found. Run 'llm models' to see available models]"
    except Exception as e:
        logger.error(f"LLM analysis failed: {e}")
        return f"[LLM analysis error: {e}]"


# =============================================================================
# EMAIL
# =============================================================================

def send_email(subject: str, body: str, to_addr: str) -> bool:
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(os.getenv("GMAIL_ACCOUNT"), os.getenv("GMAIL_PASSWORD"))

            msg = MIMEMultipart()
            msg["From"] = "Nginx Analysis Team"
            msg["To"] = to_addr
            msg["Subject"] = subject

            msg.attach(MIMEText(body, "plain"))

            server.send_message(msg)

        return True

    except smtplib.SMTPException as e:
        logger.error(f"Gmail SMTP failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Email sending failed: {e}")
        return False


# =============================================================================
# MAIN
# =============================================================================

def main():
    try:
        target_date = (datetime.now() - timedelta(days=1)).date()
        # logger.info(f"Starting nginx analytics for {target_date}")

        # Read and parse logs
        entries = read_log_file(CONFIG["log_path"], target_date)

        if not entries:
            logger.warning(f"No log entries found for {target_date}")
            sys.exit(0)

        logger.info(f"Found {len(entries)} log entries")

        # =================================================================
        # STAGE 1: Generate analytics and text report
        # =================================================================
        logger.info("STAGE 1: Generating analytics report")

        analytics = generate_analytics(entries, target_date)
        report = generate_text_report(analytics)
        logger.info("Analytics report generated successfully")

        # Log security alerts
        if analytics.get("security_alerts"):
            logger.warning(f"Security alerts detected: {len(analytics['security_alerts'])} alert(s)")
            for alert in analytics["security_alerts"]:
                logger.warning(f"[{alert['severity']}] {alert['type']}: {alert['message']}")

        # =================================================================
        # STAGE 2: Get LLM analysis
        # =================================================================
        logger.info("STAGE 2: Getting LLM analysis")
        llm_analysis = get_llm_analysis(report)

        if llm_analysis and not llm_analysis.startswith("[LLM analysis"):
            logger.info("LLM analysis completed successfully")
        else:
            logger.warning(f"LLM analysis issue: {llm_analysis}")

        # =================================================================
        # STAGE 3: Compose and send email
        # =================================================================
        logger.info("STAGE 3: Composing and sending email")

        final_report = report
        if llm_analysis and not llm_analysis.startswith("[LLM analysis"):
            final_report += f"""

DeepSeek says...
{llm_analysis}

That's all for today's Nginx analytics digest!
"""

        # Add alert indicator to subject line if there are security alerts
        subject = f"Nginx Digest for {target_date}"
        if analytics.get("security_alerts"):
            high_alerts = sum(1 for a in analytics["security_alerts"] if a["severity"] == "HIGH")
            if high_alerts > 0:
                subject = f"🔴 SECURITY ALERT - Nginx Digest for {target_date}"
            else:
                subject = f"⚠️ Alert - Nginx Digest for {target_date}"

        success = send_email(
            subject=subject,
            body=final_report,
            to_addr=CONFIG["email_to"],
        )

        if success:
            logger.info(f"Email sent successfully to {CONFIG['email_to']}")
            sys.exit(0)
        else:
            logger.error("Failed to send email")
            sys.exit(1)

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except PermissionError as e:
        logger.error(f"Permission denied: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
