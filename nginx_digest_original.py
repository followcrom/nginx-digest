#!/home/followcrom/projects/swill/swill_venv/bin/python3

from __future__ import annotations

import re
import sys
import gzip
import subprocess
import argparse
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import NamedTuple, Optional
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import geoip2

# Load environment variables from .env file
import os
from dotenv import load_dotenv
load_dotenv()

# Set up project-specific LLM configuration directory
# This ensures we use a fresh, isolated LLM config for this project
LLM_CONFIG_DIR = Path(".llm")
os.environ["LLM_USER_PATH"] = str(LLM_CONFIG_DIR)

# Now import llm after setting the environment variable
try:
    import llm
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger_warning = "llm library not installed. LLM analysis will be unavailable."

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Optional imports - graceful degradation if not available
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logger.warning("geoip2 not installed. Location data will be unavailable.")

# try:
#     from user_agents import parse as parse_user_agent
#     USER_AGENT_PARSER_AVAILABLE = True
# except ImportError:
#     USER_AGENT_PARSER_AVAILABLE = False
#     logger.warning("user-agents not installed. Device parsing will be basic.")


# =============================================================================
# CONFIGURATION - Edit these values for your setup
# =============================================================================

CONFIG = {
    # Nginx log location (supports glob patterns)
    # "log_path": "/var/log/nginx/access.log",
    "log_path": "sample_access_with_locations.log",

    # GeoIP database path (download from MaxMind)
    "geoip_db_path": "/var/lib/GeoIP/GeoLite2-City.mmdb",

    # Email settings (can be overridden by environment variables)
    "email_to": os.getenv("EMAIL_TO"),
    "email_from": os.getenv("EMAIL_FROM"),
    "email_from_name": "The Nginx Analysis Team",
    "email_subject": "Daily Nginx Analytics Digest",

    # LLM settings (using the llm library)
    "llm_model": "deepseek-chat",

    # # Filtering
    # "exclude_ips": [
    #     "127.0.0.1",
    #     # Add your own IP if you want to exclude yourself
    # ],
    # "exclude_paths": [
    #     r"^/favicon\.ico$",
    #     r"^/robots\.txt$",
    #     r"\.map$",
    #     r"^/\.well-known/",
    # ],
    # "exclude_user_agents": [
    #     r"bot",
    #     r"crawler",
    #     r"spider",
    #     r"curl",
    #     r"wget",
    #     r"python-requests",
    #     r"Go-http-client",
    #     r"HeadlessChrome",
    # ],

    # Session timeout in minutes (for calculating visit duration)
    "session_timeout_minutes": 30,

    # # Referrer filtering - exclude internal domains
    # "internal_domains": [
    #     "followcrom.com",
    #     "localhost",
    # ],

    # # Services/sites to track separately (based on server_name or path prefix)
    # "services": {
    #     # Map hostname or path prefix to friendly name
    #     # "followcrom.com": "Personal Site",
    #     # "api.followcrom.com": "API",
    # },
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
    
    @property
    def duration_seconds(self) -> int:
        return int((self.last_seen - self.first_seen).total_seconds())
    
    def add_request(self, entry: LogEntry):
        self.last_seen = entry.timestamp
        if entry.path not in self.pages:
            self.pages.append(entry.path)
        self.total_bytes += entry.size
        self.requests += 1


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


# def should_exclude(entry: LogEntry) -> bool:
#     """Check if this entry should be excluded from analysis"""
#     # Exclude specific IPs
#     if entry.ip in CONFIG["exclude_ips"]:
#         return True
    
#     # Exclude specific paths
#     for pattern in CONFIG["exclude_paths"]:
#         if re.search(pattern, entry.path, re.IGNORECASE):
#             return True
    
#     # Exclude bots/crawlers
#     for pattern in CONFIG["exclude_user_agents"]:
#         if re.search(pattern, entry.user_agent, re.IGNORECASE):
#             return True
    
#     return False


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


def parse_device_info(user_agent: str) -> dict:
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
            "os": "Unknown",
            "device": device,
            "is_bot": is_bot,
        }


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
    
    # Collect stats
    unique_visitors = len(sessions_by_ip)
    total_sessions = len(all_sessions)
    total_pageviews = sum(s.requests for s in all_sessions)
    total_bandwidth = sum(s.total_bytes for s in all_sessions)
    
    # Location breakdown
    locations = Counter()
    countries = Counter()
    for ip in sessions_by_ip.keys():
        loc = get_location(ip, geoip_reader)
        locations[f"{loc['city']}, {loc['country']}"] += 1
        countries[loc['country']] += 1
    
    # Page popularity
    page_views = Counter()
    for entry in entries:
        # Normalize paths (remove query strings for grouping)
        clean_path = entry.path.split('?')[0]
        page_views[clean_path] += 1
    
    # Device breakdown and bot detection
    devices = Counter()
    browsers = Counter()
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
    
    # Session duration stats
    session_durations = [s.duration_seconds for s in all_sessions]
    avg_duration = sum(session_durations) / len(session_durations) if session_durations else 0
    
    # Pages per session
    pages_per_session = [len(s.pages) for s in all_sessions]
    avg_pages = sum(pages_per_session) / len(pages_per_session) if pages_per_session else 0
    
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
    
    return {
        "date": target_date.isoformat(),
        "summary": {
            "unique_visitors": unique_visitors,
            "total_sessions": total_sessions,
            "total_pageviews": total_pageviews,
            "total_bandwidth_mb": round(total_bandwidth / (1024 * 1024), 2),
            "avg_session_duration_seconds": round(avg_duration),
            "avg_pages_per_session": round(avg_pages, 1),
            "human_traffic": human_traffic,
            "bot_traffic": bot_traffic,
        },
        "top_pages": dict(page_views.most_common(15)),
        "top_locations": dict(locations.most_common(10)),
        "countries": dict(countries.most_common(10)),
        "devices": dict(devices),
        "browsers": dict(browsers.most_common(8)),
        "referrers": dict(referrers.most_common(10)),
        "hourly_traffic": dict(sorted(hourly_traffic.items())),
        "services": dict(service_stats.most_common(10)),
        "status_codes": dict(status_codes),
        "bot_details": dict(bot_details.most_common(10)),
    }


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
    
    report = f"""
═══════════════════════════════════════════════════════════════════
               NGINX ANALYTICS DIGEST - {analytics['date']}
═══════════════════════════════════════════════════════════════════

SUMMARY
───────────────────────────────────────────────────────────────────
  • Unique Visitors:     {s['unique_visitors']:,}
  • Total Sessions:      {s['total_sessions']:,}
  • Total Pageviews:     {s['total_pageviews']:,}
  • Human Traffic:       {s['human_traffic']:,} ({s['human_traffic']/s['total_pageviews']*100:.1f}%)
  • Bot Traffic:         {s['bot_traffic']:,} ({s['bot_traffic']/s['total_pageviews']*100:.1f}%)
  • Bandwidth Used:      {s['total_bandwidth_mb']:.2f} MB
  • Avg Session Length:  {format_duration(s['avg_session_duration_seconds'])}
  • Avg Pages/Session:   {s['avg_pages_per_session']}

TOP PAGES
───────────────────────────────────────────────────────────────────
"""
    for page, count in list(analytics["top_pages"].items())[:10]:
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
BROWSERS
───────────────────────────────────────────────────────────────────
"""
        for browser, count in list(analytics["browsers"].items())[:6]:
            report += f"  {count:>5}  {browser}\n"
    
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
BOT ACTIVITY
───────────────────────────────────────────────────────────────────
"""
        for bot_name, count in analytics["bot_details"].items():
            report += f"  {count:>5}  {bot_name}\n"

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
        print(f"Using LLM model:", CONFIG["llm_model"])

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
    """Send email via Gmail SMTP or system mail command

    Args:
        subject: Email subject line
        body: Email body (plain text)
        to_addr: Recipient email address

    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(os.getenv("GMAIL_ACCOUNT"), os.getenv("GMAIL_PASSWORD"))

            msg = MIMEMultipart()
            msg["From"] = "The Nginx Analysis Team"
            msg["To"] = to_addr
            msg["Subject"] = subject

            msg.attach(MIMEText(body, "plain"))

            server.send_message(msg)
            logger.info(f"Email sent to {to_addr}")

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

def prompt_continue(stage_name: str) -> bool:
    """Prompt user to continue to next stage"""
    response = input(f"\n{'='*70}\nContinue to stage {stage_name}? (y/n): ").strip().lower()
    return response in ['y', 'yes']


def main():
    parser = argparse.ArgumentParser(description="Generate nginx analytics digest")
    parser.add_argument(
        "--date",
        type=str,
        help="Date to analyze (YYYY-MM-DD). Defaults to yesterday.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print report to stdout instead of emailing",
    )
    # parser.add_argument(
    #     "--no-llm",
    #     action="store_true",
    #     help="Skip LLM analysis",
    # )
    # parser.add_argument(
    #     "--output-json",
    #     type=str,
    #     help="Save raw analytics data to JSON file",
    # )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive mode: prompt between stages",
    )
    args = parser.parse_args()

    # Determine target date
    if args.date:
        target_date = datetime.strptime(args.date, "%Y-%m-%d").date()
    else:
        target_date = (datetime.now() - timedelta(days=2)).date()

    print(f"Analyzing nginx logs for {target_date}...")

    # Read and parse logs
    entries = read_log_file(CONFIG["log_path"], target_date)

    if not entries:
        print(f"No log entries found for {target_date}")
        sys.exit(0)

    print(f"Found {len(entries)} log entries")

    # =================================================================
    # STAGE 1: Generate analytics and text report
    # =================================================================
    print("\n" + "="*70)
    print("STAGE 1: GENERATING ANALYTICS REPORT")
    print("="*70)

    analytics = generate_analytics(entries, target_date)
    print("Analytics:", json.dumps(analytics, indent=2))

    # # Save JSON if requested
    # if args.output_json:
    #     with open(args.output_json, 'w') as f:
    #         json.dump(analytics, f, indent=2)
    #     print(f"Saved analytics to {args.output_json}")

    report = generate_text_report(analytics)

    # Print the report
    print("\n" + report)

    # Check if user wants to continue to Stage 2
    if args.interactive:
        if not prompt_continue("2: LLM Analysis"):
            print("\nStopped after Stage 1. Exiting.")
            sys.exit(0)

    # =================================================================
    # STAGE 2: Get LLM analysis
    # =================================================================
    llm_analysis = ""
    print("\n" + "="*70)
    print("STAGE 2: GETTING LLM ANALYSIS")
    print("="*70)

    llm_analysis = get_llm_analysis(report)

    # Print the LLM analysis
    print("\n" + "="*70)
    print("AI ANALYSIS")
    print("="*70)
    print(llm_analysis)
    print("="*70)

    # Check if user wants to continue to Stage 3
    if args.interactive and not args.dry_run:
        if not prompt_continue("3: Send Email"):
            print("\nStopped after Stage 2. Exiting.")
            sys.exit(0)

    # =================================================================
    # STAGE 3: Compose and send email
    # =================================================================
    final_report = report
    if llm_analysis:
        final_report += f"""
        DeepSeek says...
{llm_analysis}
That's all for today's nginx analytics digest!
"""

    if args.dry_run:
        print("\n" + "=" * 70)
        print("DRY RUN - Would send the following email:")
        print("=" * 70)
        print(f"To: {CONFIG['email_to']}")
        print(f"From: {CONFIG['email_from']}")
        print(f"Subject: {CONFIG['email_subject']} - {target_date}")
        print("=" * 70)
        print(final_report)
    else:
        print("\n" + "="*70)
        print("STAGE 3: SENDING EMAIL")
        print("="*70)

        subject = f"{CONFIG['email_subject']} - {target_date}"
        success = send_email(
            subject=subject,
            body=final_report,
            to_addr=CONFIG["email_to"],
        )

        if success:
            print(f"✓ Email sent successfully to {CONFIG['email_to']}")
        else:
            print("✗ Failed to send email. Printing report to stdout:")
            print(final_report)
            sys.exit(1)


if __name__ == "__main__":
    main()
