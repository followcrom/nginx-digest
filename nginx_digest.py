#!/usr/bin/env python3
"""
Nginx Analytics Daily Digest
============================
Parses nginx access logs, classifies every session as bot / unverified / human
using evidence-based rules, generates a text report, gets LLM commentary, and
sends a daily email digest.

Classification philosophy
-------------------------
A session is only called HUMAN when there is positive evidence of a real
browser: a browser user agent that also fetched the page's static assets
(CSS/JS/images) or fired the optional JS beacon.  Any single "strong" bot
signal (bot/tool user agent, probe path, malformed request, IP-address Host
header, datacenter network, all-error session, ...) makes a session a BOT.
Sessions with a browser-like user agent but no corroborating evidence are
reported as UNVERIFIED and treated as probable bots, never as visitors.

Run `python nginx_digest.py --help` for the CLI (dry runs, per-session dumps,
alternative log files and dates).
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import logging
import os
import re
import smtplib
import socket
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from itertools import chain
from pathlib import Path
from typing import NamedTuple, Optional
from urllib.parse import urlparse

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent

# Load .env from the same directory as this script
load_dotenv(SCRIPT_DIR / '.env')

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
logging.getLogger("httpx").setLevel(logging.WARNING)

# Use a project-specific LLM configuration directory
os.environ.setdefault("LLM_USER_PATH", str(SCRIPT_DIR / ".llm"))

try:
    import llm
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.warning("llm not installed. LLM commentary will be unavailable.")

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
    logger.warning("user-agents not installed. Browser/OS breakdown will use basic string matching.")


# =============================================================================
# CONFIGURATION
# =============================================================================

CONFIG = {
    # Nginx log location. Rotated siblings (access.log.1, access.log.*.gz) are read too.
    "log_path": "/var/log/nginx/access.log",

    # GeoIP databases (download with geoipupdate; add GeoLite2-ASN to EditionIDs in GeoIP.conf)
    "geoip_db_path": "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "asn_db_path": "/var/lib/GeoIP/GeoLite2-ASN.mmdb",

    # Email settings (from .env)
    "email_to": os.getenv("EMAIL_TO"),

    # LLM settings (using the llm library)
    "llm_model": "deepseek-chat",

    # Used in build_sessions() to decide when to create a new session vs. continuing an existing one
    "session_timeout_minutes": 30,

    # Hostnames this server legitimately serves, e.g. SITE_HOSTS=followcrom.com,www.followcrom.com
    # in .env. Requests whose Host header is a bare IP address are always scanner traffic; if this
    # list is non-empty, any Host not in it is treated the same way.
    "site_hosts": [h.strip().lower() for h in os.getenv("SITE_HOSTS", "").split(",") if h.strip()],

    # Optional JS beacon (see README). A session that requests this path executed JavaScript,
    # which is the strongest available evidence of a real browser.
    "beacon_path": "/beacon.gif",

    # Reverse-DNS check for sessions claiming to be Googlebot/Bingbot/etc.
    "verify_crawler_dns": True,
    "max_dns_lookups": 40,
    "dns_timeout_seconds": 3,

    # Chrome/Firefox major versions older than this are treated as spoofed (nobody browses with them)
    "min_modern_browser_version": 100,

    # Rolling history so the report and the LLM can compare against a baseline
    "history_path": str(SCRIPT_DIR / "digest_history.jsonl"),
    "history_days": 7,

    # Human evidence thresholds. A fresh browser on this site pulls in at least four CSS/JS files, so
    # requiring two keeps "homepage + one image" scanners out. A same-site navigation only counts as
    # evidence if it happens at least this many seconds after arrival (form-spam bots do it in 0-3 s).
    "min_render_assets": 2,
    "min_navigation_seconds": 5,

    # Treat a hosting/cloud-provider IP as decisive on its own (True) or as one medium signal (False).
    # True is right for a small site; set False if you expect real visitors via corporate/commercial VPNs.
    "datacenter_is_decisive": True,
}

# Known probe/attack patterns. A single request matching one of these marks the whole session as a bot.
PROBE_PATTERNS = [
    '.env', 'wp-', 'admin.php', 'xmlrpc', '.php',
    'phpmyadmin', 'mysql', 'wp-login', 'wp-admin',
    '.git', '.aws', '.ssh', '.svn', '.ds_store', 'config.', 'backup', '.sql', '.bak',
    'shell', 'eval-stdin', 'vendor/', 'owa/auth',
    'solr/', 'console/', 'manager/', 'api/jsonws',
    'cgi-bin', 'jenkins', 'actuator', 'telescope',
    '.aspx', '.asp', 'admin/', 'administrator/',
    'boaform', 'hnap1', 'geoserver', 'druid/', '_ignition', 'debug/default',
    'autodiscover', 'ecp/', 'remote/login', 'fgt_lang', 'cf_scripts',
    'phpinfo', 'wlwmanifest', 'ftpsync',
    '/id_rsa', '/etc/passwd', 'passwd', '/proc/self', '%2e%2e', '../',
    'nice ports', 'trinity', 'x-ray', 'aws/credentials', 'credentials.json',
    '.yml', '.yaml', '.toml', '.ini', 'docker-compose', 'dockerfile',
    'server-status', 'nginx-status', 'metrics', 'graphql', 'swagger', 'appsettings',
    'mgmt/', 'wsman', 'evox/', 'onvif', 'cgi/', 'hudson', 'ws_utc',
]

# Paths that are exempt from PROBE_PATTERNS even though they contain a pattern.
# Add your own legitimate paths here (e.g. a real .php contact form).
PROBE_ALLOWLIST = [
    '/contact/contact.php',
]

# Sub-resources a real browser fetches while rendering a page on this site. Deliberately excludes
# documents that bots fetch on their own (.txt, .xml, .json, .pdf) so that e.g. a robots.txt
# fetch can never count as evidence of a browser.
STATIC_EXTENSIONS = (
    '.css', '.js', '.mjs', '.map', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.avif', '.svg',
    '.woff', '.woff2', '.ttf', '.otf', '.eot', '.webmanifest',
)

# The subset that only a rendering browser fetches. Scanners parse HTML for images and icons
# (favicon hashing, screenshots), but they do not pull stylesheets, scripts and fonts.
RENDER_ASSET_EXTENSIONS = ('.css', '.js', '.mjs', '.woff', '.woff2', '.ttf', '.otf')

# Requested by browsers and by scanners alike (favicon hashing is a fingerprinting technique),
# so these count as neither a page nor an asset.
NEUTRAL_PATHS = ('/favicon.ico', '/apple-touch-icon.png', '/apple-touch-icon-precomposed.png')

# Technical/crawler endpoints
TECHNICAL_PATHS = ('robots.txt', 'sitemap', '.well-known/', 'ads.txt', 'security.txt', 'humans.txt')

# Methods a browser uses when a person is browsing a website
BROWSER_METHODS = {'GET', 'POST', 'HEAD', 'OPTIONS'}

# Substrings of ASN organisation names that identify hosting/cloud providers.
# Traffic from these networks is automated in practically every case on a small site.
# Cloudflare, Fastly and Apple are excluded because iCloud Private Relay and Cloudflare WARP
# route real Safari/Chrome users through them.
DATACENTER_ASN_EXCLUDE = ['cloudflare', 'fastly', 'apple']

# Networks that exist to scan the internet. Decisive on their own; the name is used as the bot name.
SCANNER_ASNS = {
    "AS10439": "Shodan (CariNet)",
    "AS213412": "ONYPHE",
    "AS398324": "Censys",
    "AS398705": "Censys",
    "AS398722": "Censys",
}

DATACENTER_ASN_KEYWORDS = [
    'amazon', 'aws', 'google cloud', 'google llc', 'microsoft', 'azure', 'digitalocean',
    'linode', 'akamai connected cloud', 'hetzner', 'ovh', 'vultr', 'choopa', 'constant company',
    'alibaba', 'aliyun', 'tencent', 'huawei cloud', 'oracle', 'leaseweb', 'contabo',
    'scaleway', 'online s.a.s', 'm247', 'datacamp', 'servers.com', 'psychz', 'hostinger',
    'namecheap', 'godaddy', 'ionos', '1&1', 'zenlayer', 'ucloud', 'kamatera',
    'hostwinds', 'colocrossing', 'quadranet', 'ipxo', 'packethub', 'hivelocity',
    'limestone', 'g-core', 'gcore', 'interserver', 'sharktech', 'frantech', 'buyvm',
    'ramnode', 'hostdime', 'webnx', 'servermania', 'clouvider', 'velia', 'netcup',
    'aeza', 'stark industries', 'melbikomas', '3xk tech', 'ipvolume', 'greencloud',
    'hostkey', 'flyservers', 'serverion', 'hostslick', 'eonix', 'hurricane electric',
    'zomro', 'bl networks', 'cogent', 'terrahost', 'timeweb', 'selectel', 'reg.ru',
    'firstbyte', 'hostglobal', 'kaopu', 'starcrecium', 'bitweb', 'joyent', 'rackspace',
    'softlayer', 'ibm cloud', 'upcloud', 'exoscale', 'fly.io',
    'heroku', 'vercel', 'netlify', 'gthost', 'shock hosting', 'nocix', 'wholesale internet',
    # seen in this site's logs, 2026-09
    'mevspace', 'lightnode', 'light node', 'tzulo', 'valence technology', 'colocation',
    'dedik', 'omniline', 'akile', 'hydra communications', 'internet vikings', 'techoff',
    'omegatech', 'feo prest', 'xtom', 'tc datacenter',
    'datacenter', 'data center', 'hosting', 'server', 'cloud', 'vps', 'dedicated', 'colo',
]

# Known crawler user agents: (category, display name, regex). Order matters: first match wins.
# Categories: search, ai, seo, social, scanner, tool, bot (generic).
BOT_UA_PATTERNS: list[tuple[str, str, str]] = [
    # --- search engines (verifiable via reverse DNS) ---
    ("search", "Googlebot", r"googlebot|google-inspectiontool|storebot-google|googleother|google-site-verification"),
    ("search", "Bingbot", r"bingbot|bingpreview|adidxbot|msnbot"),
    ("search", "Applebot", r"applebot"),
    ("search", "DuckDuckBot", r"duckduckbot|duckduckgo"),
    ("search", "YandexBot", r"yandex"),
    ("search", "Baiduspider", r"baiduspider"),
    ("search", "Yahoo Slurp", r"slurp"),
    ("search", "SeznamBot", r"seznambot"),
    ("search", "Sogou", r"sogou"),
    ("search", "PetalBot", r"petalbot|aspiegelbot"),
    ("search", "Naver Yeti", r"yeti/|naverbot"),
    ("search", "Qwantbot", r"qwantify|qwantbot"),
    ("search", "MojeekBot", r"mojeekbot"),
    ("search", "CocCocBot", r"coccocbot"),
    ("search", "archive.org", r"archive\.org_bot|ia_archiver"),
    # --- AI / LLM crawlers and agents ---
    ("ai", "GPTBot", r"gptbot"),
    ("ai", "ChatGPT-User", r"chatgpt-user"),
    ("ai", "OAI-SearchBot", r"oai-searchbot"),
    ("ai", "ClaudeBot", r"claudebot|claude-web|claude-user|claude-searchbot|anthropic-ai"),
    ("ai", "PerplexityBot", r"perplexitybot|perplexity-user"),
    ("ai", "Bytespider", r"bytespider|bytedance"),
    ("ai", "CCBot", r"ccbot"),
    ("ai", "Amazonbot", r"amazonbot"),
    ("ai", "Meta-ExternalAgent", r"meta-externalagent|meta-externalfetcher|facebookbot"),
    ("ai", "Google-Extended", r"google-extended"),
    ("ai", "Applebot-Extended", r"applebot-extended"),
    ("ai", "cohere-ai", r"cohere-ai"),
    ("ai", "Diffbot", r"diffbot"),
    ("ai", "YouBot", r"youbot"),
    ("ai", "Timpibot", r"timpibot"),
    ("ai", "ImagesiftBot", r"imagesiftbot"),
    ("ai", "MistralAI", r"mistralai"),
    ("ai", "DuckAssistBot", r"duckassistbot"),
    ("ai", "Omgili/Webz.io", r"omgili|webzio"),
    ("ai", "PanguBot", r"pangubot"),
    ("ai", "iaskspider", r"iaskspider"),
    # --- SEO / marketing / uptime tools ---
    ("seo", "AhrefsBot", r"ahrefsbot|ahrefssiteaudit"),
    ("seo", "SemrushBot", r"semrushbot|siteauditbot|splitsignalbot"),
    ("seo", "MJ12bot", r"mj12bot"),
    ("seo", "DotBot", r"dotbot"),
    ("seo", "BLEXBot", r"blexbot"),
    ("seo", "DataForSEO", r"dataforseobot"),
    ("seo", "Serpstat", r"serpstatbot"),
    ("seo", "Screaming Frog", r"screaming frog"),
    ("seo", "Barkrowler", r"barkrowler"),
    ("seo", "Awario", r"awariobot|awariosmartbot|awariorssbot"),
    ("seo", "SEOkicks", r"seokicks"),
    ("seo", "Linkdex", r"linkdexbot"),
    ("seo", "Sistrix", r"sistrix"),
    ("seo", "Cincraw", r"cincraw"),
    ("seo", "Uptime monitor", r"uptimerobot|pingdom|statuscake|site24x7|uptime\.com|freshping|betteruptime|hetrixtools|updown\.io|digitalocean uptime|uptime probe|uptime-kuma"),
    # --- link previews / social unfurlers ---
    ("social", "facebookexternalhit", r"facebookexternalhit|facebookcatalog"),
    ("social", "Twitterbot", r"twitterbot"),
    ("social", "LinkedInBot", r"linkedinbot"),
    ("social", "Slackbot", r"slackbot|slack-imgproxy"),
    ("social", "Discordbot", r"discordbot"),
    ("social", "TelegramBot", r"telegrambot"),
    ("social", "WhatsApp", r"whatsapp"),
    ("social", "Pinterest", r"pinterestbot|pinterest/"),
    ("social", "Redditbot", r"redditbot"),
    ("social", "Embedly", r"embedly"),
    ("social", "Skype", r"skypeuripreview"),
    ("social", "Mastodon", r"mastodon"),
    ("social", "Bluesky", r"bluesky cardyb"),
    ("social", "Iframely", r"iframely"),
    # --- internet-wide scanners and vulnerability tools ---
    ("scanner", "zgrab", r"zgrab"),
    ("scanner", "masscan", r"masscan"),
    ("scanner", "Nmap", r"nmap"),
    ("scanner", "Nikto", r"nikto"),
    ("scanner", "sqlmap", r"sqlmap"),
    ("scanner", "Censys", r"censys"),
    ("scanner", "Expanse/Palo Alto", r"expanse|paloaltonetworks"),
    ("scanner", "InternetMeasurement", r"internetmeasurement|internet-measurement"),
    ("scanner", "Shodan", r"shodan"),
    ("scanner", "Netcraft", r"netcraft"),
    ("scanner", "LeakIX", r"leakix|l9explore|l9tcpid"),
    ("scanner", "Nuclei", r"nuclei"),
    ("scanner", "WPScan", r"wpscan"),
    ("scanner", "Directory brute-forcer", r"gobuster|dirbuster|\bdirb\b|ffuf|feroxbuster"),
    ("scanner", "Acunetix", r"acunetix"),
    ("scanner", "Nessus/OpenVAS", r"nessus|openvas"),
    ("scanner", "ProjectDiscovery", r"projectdiscovery"),
    ("scanner", "BBOT", r"\bbbot\b"),
    ("scanner", "Odin", r"getodin|\bodin\b"),
    ("scanner", "NetSystemsResearch", r"netsystemsresearch"),
    ("scanner", "Stretchoid", r"stretchoid"),
    ("scanner", "BinaryEdge", r"binaryedge"),
    ("scanner", "Criminal IP", r"criminalip"),
    ("scanner", "Morfeus", r"morfeus"),
    ("scanner", "ZmEu", r"zmeu"),
    ("scanner", "'Hello World' scanner", r"^hello,? world"),
    ("scanner", "Mozlila (typo UA)", r"mozlila"),
    ("scanner", "Headless browser", r"headlesschrome|phantomjs|selenium|puppeteer|playwright"),
    # --- HTTP client libraries and CLI tools ---
    ("tool", "curl", r"^curl/|\bcurl/|libcurl"),
    ("tool", "wget", r"\bwget"),
    ("tool", "python-requests", r"python-requests"),
    ("tool", "python-urllib", r"python-urllib|python/\d|^python"),
    ("tool", "aiohttp", r"aiohttp"),
    ("tool", "httpx", r"\bhttpx/"),
    ("tool", "Go-http-client", r"go-http-client"),
    ("tool", "Java", r"^java/|\bjava/\d|jakarta commons"),
    ("tool", "okhttp", r"okhttp"),
    ("tool", "Apache-HttpClient", r"apache-httpclient|httpclient/"),
    ("tool", "libwww-perl", r"libwww-perl|lwp-trivial|lwp::simple"),
    ("tool", "node-fetch/undici", r"node-fetch|undici"),
    ("tool", "axios", r"axios/"),
    ("tool", "Ruby", r"^ruby|\bruby/|faraday|rest-client|typhoeus"),
    ("tool", "PHP", r"^php/|guzzlehttp|http_request2|symfony httpclient"),
    ("tool", "WinHTTP", r"winhttp|ms-webservices"),
    ("tool", "PowerShell", r"powershell"),
    ("tool", "Postman/Insomnia", r"postmanruntime|insomnia"),
    ("tool", "colly", r"colly"),
    ("tool", "got", r"^got \(|\bgot/\d"),
    ("tool", "reqwest/hyper", r"reqwest|^hyper/"),
    ("tool", "fasthttp", r"fasthttp"),
    ("tool", "Dart", r"dart:io|dart/\d"),
    ("tool", "cpp-httplib", r"cpp-httplib"),
    ("tool", "HTTPie", r"httpie"),
    ("tool", "Deno", r"^deno/"),
    ("tool", "Bun", r"^bun/"),
    ("tool", "Nutch", r"nutch"),
    ("tool", "Scrapy", r"scrapy"),
    # --- generic catch-alls (must be last) ---
    ("bot", "Generic bot", r"bot(?:[/;)\s]|$)|\bbot\b|crawler|spider|\bcrawl(?:ing|er)?\b|scrap(?:e|er|ing)\b|fetcher|monitor(?:ing)?\b|\bprobe\b|\bscan(?:ner)?\b|feedparser|\brss\b"),
]
BOT_UA_REGEX = [(cat, name, re.compile(pat, re.IGNORECASE)) for cat, name, pat in BOT_UA_PATTERNS]

# Reverse-DNS suffixes that prove a claimed crawler identity
CRAWLER_DNS_SUFFIXES = {
    "Googlebot": (".googlebot.com", ".google.com"),
    "Bingbot": (".search.msn.com",),
    "Applebot": (".applebot.apple.com",),
    "YandexBot": (".yandex.ru", ".yandex.net", ".yandex.com"),
    "Baiduspider": (".crawl.baidu.com", ".crawl.baidu.jp"),
    "Yahoo Slurp": (".crawl.yahoo.net",),
    "PetalBot": (".petalsearch.com",),
    "Amazonbot": (".crawl.amazonbot.amazon",),
}

# Security alert thresholds
ALERT_THRESHOLDS = {
    "suspicious_requests": 100,        # Alert if >100 probe requests/day
    "single_ip_requests": 200,         # Alert if single IP makes >200 requests
    "human_error_percentage": 20,      # Alert if >20% of verified-human requests are 4xx/5xx (broken links)
    "human_error_min_requests": 10,    # ...but only once humans made at least this many requests
    "suspicious_spike": 50,            # Alert if one probe pattern >50 hits
    "server_errors": 50,               # Alert if >50 5xx responses
    # Once a 7-day baseline exists, the probe-volume, single-IP and fake-crawler alerts only fire
    # when today exceeds this multiple of the baseline average (background scanning is not news).
    "baseline_multiplier": 2.0,
}

# Signal weights. Score >= BOT_SCORE_THRESHOLD => bot. STRONG signals are decisive on their own.
STRONG = 3
BOT_SCORE_THRESHOLD = 3
SIGNAL_WEIGHTS = {
    # strong: decisive on their own
    "ua_bot": STRONG,
    "ua_missing": STRONG,
    "probe_path": STRONG,
    "malformed_request": STRONG,
    "ip_host_header": STRONG,
    "unknown_host": STRONG,
    "absolute_uri": STRONG,
    "odd_method": STRONG,
    "all_errors": STRONG,
    "datacenter_asn": STRONG,     # downgraded to 2 when CONFIG["datacenter_is_decisive"] is False
    "scanner_asn": STRONG,
    "impostor_crawler": STRONG,
    "no_accept_language": STRONG,
    # medium: two of these make a bot
    "ua_not_browser": 2,
    "no_assets": 2,
    "single_html_only": 2,
    "obsolete_browser": 2,
    "high_request_rate": 2,
    "ip_ua_rotation": 2,
    "ip_also_probed": 2,
    "head_only": 2,
    "no_sec_fetch": 2,
    # weak: supporting evidence only
    "assets_only": 1,
    "images_only": 1,
    "no_referer_multi_page": 1,
    "excessive_page_depth": 1,
    "technical_endpoint": 1,
    "consistent_timing": 1,
    "mostly_errors": 1,
}

SIGNAL_LABELS = {
    "ua_bot": "Bot/tool user agent",
    "ua_missing": "Empty or missing user agent",
    "ua_not_browser": "User agent is neither a known bot nor a real browser",
    "assets_only": "Fetched assets/images but never a page",
    "probe_path": "Requested probe/attack paths",
    "malformed_request": "Malformed request line (raw TLS/binary/garbage)",
    "ip_host_header": "Host header was the server's IP, not a domain",
    "unknown_host": "Host header not one of this site's domains",
    "absolute_uri": "Proxy-style absolute URI request",
    "odd_method": "Non-browser HTTP method (PROPFIND, CONNECT, ...)",
    "all_errors": "Every request failed (4xx/5xx)",
    "datacenter_asn": "Hosting/cloud provider network",
    "scanner_asn": "Known internet-scanner network (Shodan, Censys, ONYPHE)",
    "images_only": "Fetched images/icons but no CSS/JS",
    "impostor_crawler": "Claimed to be a search crawler but reverse DNS disagrees",
    "no_accept_language": "Browser UA but no Accept-Language header",
    "no_assets": "Fetched pages but never any CSS/JS/images",
    "single_html_only": "Single HTML fetch, no assets",
    "obsolete_browser": "Browser version nobody uses any more",
    "high_request_rate": "High page-request rate",
    "ip_ua_rotation": "IP used 3+ different user agents today",
    "ip_also_probed": "Same IP sent probe/attack requests today",
    "head_only": "HEAD requests only",
    "no_sec_fetch": "Browser UA but no Sec-Fetch headers",
    "no_referer_multi_page": "Navigated several pages with no Referer",
    "excessive_page_depth": "Crawled an unusual number of pages",
    "technical_endpoint": "Fetched robots.txt/sitemap",
    "consistent_timing": "Machine-regular request timing",
    "mostly_errors": "Most requests failed",
}

STATUS_LABELS = {
    200: "OK",
    301: "redirect (http→https, www→apex, /index.html→/)",
    304: "not modified (browser revalidated a cached asset)",
    400: "bad request (garbage/TLS-on-HTTP)",
    401: "auth required (/w2w/)",
    403: "forbidden (blockips.conf or denied path)",
    404: "not found (includes block_probes.conf hits)",
    405: "method not allowed",
    429: "rate-limited by nginx (limit_req)",
    444: "connection closed by nginx without a response",
    499: "client closed the connection early",
    502: "bad gateway (momcon app on :5000 down?)",
    504: "gateway timeout",
}

CATEGORY_LABELS = {
    "search": "Search engine crawlers",
    "ai": "AI / LLM crawlers",
    "seo": "SEO & monitoring tools",
    "social": "Link-preview / social bots",
    "scanner": "Scanners & vulnerability probes",
    "tool": "HTTP libraries & CLI tools",
    "bot": "Other self-declared bots",
    "impostor": "Fake search crawlers",
    "probe": "Probes wearing browser UAs",
    "datacenter": "Datacenter IPs with browser UAs",
    "behavioural": "Behavioural (browser UA, bot behaviour)",
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
    protocol: str
    status: int
    size: int
    referer: str
    user_agent: str
    host: str
    accept_language: Optional[str]   # only with the extended log format (see README)
    sec_fetch_mode: Optional[str]    # only with the extended log format (see README)
    malformed: bool                  # request line was not "METHOD PATH PROTOCOL"


class VisitorSession:
    """All requests from one IP within the session timeout window."""

    def __init__(self, ip: str, first_seen: datetime):
        self.ip = ip
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.timestamps: list[datetime] = []
        self.requests = 0
        self.total_bytes = 0
        self.pages: list[str] = []            # unique non-static, non-probe paths
        self.static_requests = 0
        self.render_asset_requests = 0        # CSS/JS/fonts: only a rendering browser fetches these
        self.probe_paths: list[str] = []
        self.malformed = 0
        self.methods: Counter = Counter()
        self.statuses: Counter = Counter()
        self.user_agents: list[str] = []
        self.hosts: set[str] = set()
        self.host_counts: Counter = Counter()   # requests per Host header (several sites share the log)
        self.referer_requests = 0
        self.page_requests_with_referer = 0
        self.internal_nav_requests = 0   # page requests whose Referer is one of our own pages
        self.technical_endpoint = False
        self.beacon = False
        self.absolute_uri = False
        self.accept_language_seen: Optional[bool] = None   # None = header not logged
        self.sec_fetch_seen: Optional[bool] = None
        self.page_request_count = 0   # requests to non-static paths (counts repeats)

        # Filled in by classify_session()
        self.verdict = "unverified"   # "bot" | "unverified" | "human"
        self.score = 0
        self.reasons: list[str] = []
        self.bot_category: Optional[str] = None
        self.bot_name: Optional[str] = None
        self.asn: Optional[str] = None
        self.asn_org: Optional[str] = None
        self.country: str = "Unknown"
        self.city: str = "Unknown"

    # ---- derived properties -------------------------------------------------

    @property
    def duration_seconds(self) -> int:
        return int((self.last_seen - self.first_seen).total_seconds())

    @property
    def non_static_requests(self) -> int:
        """Pages, probes and malformed lines: everything except sub-resources a page pulls in."""
        return self.page_request_count + len(self.probe_paths) + self.malformed

    @property
    def non_static_per_minute(self) -> float:
        """Rate of page-like requests. Assets are excluded because one page can pull in dozens."""
        return self.non_static_requests / max(self.duration_seconds, 10) * 60

    @property
    def primary_user_agent(self) -> str:
        return self.user_agents[0] if self.user_agents else "-"

    @property
    def error_requests(self) -> int:
        return sum(c for s, c in self.statuses.items() if s >= 400)

    # ---- request ingestion --------------------------------------------------

    def add_request(self, entry: LogEntry):
        self.last_seen = entry.timestamp
        self.timestamps.append(entry.timestamp)
        self.requests += 1
        self.total_bytes += entry.size
        self.methods[entry.method] += 1
        self.hosts.add(entry.host.lower())
        self.host_counts[entry.host.lower()] += 1

        if entry.user_agent not in self.user_agents:
            self.user_agents.append(entry.user_agent)

        if entry.malformed:
            self.malformed += 1
            return

        # Statuses are tracked for well-formed requests only (malformed lines are always 400)
        self.statuses[entry.status] += 1

        clean_path = entry.path.split('?', 1)[0]

        if entry.path.lower().startswith(('http://', 'https://')):
            self.absolute_uri = True

        if CONFIG["beacon_path"] and clean_path == CONFIG["beacon_path"]:
            self.beacon = True
            return

        if is_probe_request(clean_path, entry.status):
            self.probe_paths.append(clean_path)
        elif is_neutral_path(clean_path):
            pass
        elif is_static_resource(clean_path):
            self.static_requests += 1
            if clean_path.lower().endswith(RENDER_ASSET_EXTENSIONS):
                self.render_asset_requests += 1
        else:
            self.page_request_count += 1
            if clean_path not in self.pages:
                self.pages.append(clean_path)
            if entry.referer != "-":
                self.page_requests_with_referer += 1
                seconds_in = (entry.timestamp - self.first_seen).total_seconds()
                if (referer_is_internal(entry.referer, entry.host, clean_path)
                        and seconds_in >= CONFIG["min_navigation_seconds"]):
                    self.internal_nav_requests += 1

        if entry.referer != "-":
            self.referer_requests += 1

        if any(tp in clean_path.lower() for tp in TECHNICAL_PATHS):
            self.technical_endpoint = True

        # Extended-format headers: only meaningful for document requests
        if entry.accept_language is not None and not is_static_resource(clean_path):
            present = entry.accept_language not in ("", "-")
            self.accept_language_seen = (self.accept_language_seen or False) or present
        if entry.sec_fetch_mode is not None and not is_static_resource(clean_path):
            present = entry.sec_fetch_mode not in ("", "-")
            self.sec_fetch_seen = (self.sec_fetch_seen or False) or present


def is_static_resource(path: str) -> bool:
    return path.lower().endswith(STATIC_EXTENSIONS)


def is_neutral_path(path: str) -> bool:
    """Favicons and touch icons in any format: browsers and scanners alike fetch them
    (Shodan requests /images/favs/favicon-32x32.png for its favicon-hash fingerprint)."""
    p = path.lower()
    return p in NEUTRAL_PATHS or p.endswith('.ico') or 'favicon' in p or 'apple-touch-icon' in p


def is_probe_path(path: str) -> bool:
    """True if the path matches a known probe pattern and is not allow-listed."""
    p = path.lower()
    if any(p == a or p.startswith(a) for a in PROBE_ALLOWLIST):
        return False
    return any(pattern in p for pattern in PROBE_PATTERNS)


# Statuses that prove the resource exists on this server. A pattern-matching path that the server
# actually served (e.g. a real .php page on this site) is a page, not a probe.
EXISTS_STATUSES = {200, 201, 204, 206, 304}


def is_probe_request(path: str, status: int) -> bool:
    """A probe is a request for a suspicious path that the server did not serve."""
    return status not in EXISTS_STATUSES and is_probe_path(path)


def host_is_ours(host: str) -> bool:
    """True if the Host header is one of CONFIG['site_hosts'] or a subdomain of one."""
    h = host.lower().split(":")[0]
    return any(h == s or h.endswith("." + s) for s in CONFIG["site_hosts"])


def referer_is_internal(referer: str, request_host: str, request_path: str) -> bool:
    """True if the Referer is a *different* page of our own site: a navigation within the site.

    A Referer equal to the requested path is not navigation. Browsers never send one when following
    a redirect, but some scanning tools set Referer to the URL they were redirected from.
    """
    try:
        parsed = urlparse(referer)
    except ValueError:
        return False
    ref_host = parsed.netloc.lower().split(":")[0]
    if not ref_host:
        return False
    ref_path = parsed.path or "/"
    if ref_path.rstrip("/") == request_path.rstrip("/"):
        return False
    if host_is_ours(ref_host):
        return True
    return request_host not in ("-", "") and ref_host == request_host.lower().split(":")[0]


def looks_like_browser(user_agent: str) -> bool:
    """A user agent that claims to be a mainstream browser (may still be spoofed)."""
    ua = user_agent.lower()
    if "mozilla/" not in ua:
        return False
    return any(b in ua for b in ("chrome/", "crios/", "firefox/", "fxios/", "safari/", "edg/", "opr/", "samsungbrowser/"))


_BROWSER_VERSION_RE = re.compile(r"(?:chrome|crios|firefox|fxios)/(\d+)", re.IGNORECASE)
_SAFARI_VERSION_RE = re.compile(r"version/(\d+)[\d.]*\s.*safari/", re.IGNORECASE)
_IOS_VERSION_RE = re.compile(r"(?:iphone|cpu) os (\d+)_", re.IGNORECASE)
MIN_MODERN_SAFARI_VERSION = 15   # Safari/iOS 15 shipped in 2021; older ones are scanner UA strings


def obsolete_browser(user_agent: str) -> bool:
    """A browser version nobody browses with any more: old Chrome/Firefox/Safari/iOS, MSIE, Windows XP-7."""
    ua = user_agent.lower()
    if "msie" in ua or "trident/" in ua:
        return True
    if "windows nt 5" in ua or "windows nt 6.0" in ua or "windows nt 6.1" in ua:
        return True
    m = _BROWSER_VERSION_RE.search(user_agent)
    if m and int(m.group(1)) < CONFIG["min_modern_browser_version"]:
        return True
    m = _SAFARI_VERSION_RE.search(user_agent)
    if m and int(m.group(1)) < MIN_MODERN_SAFARI_VERSION:
        return True
    m = _IOS_VERSION_RE.search(user_agent)
    if m and int(m.group(1)) < MIN_MODERN_SAFARI_VERSION:
        return True
    return False


def match_bot_user_agent(user_agent: str) -> Optional[tuple[str, str]]:
    """Return (category, name) if the user agent identifies an automated client."""
    if not user_agent or user_agent in ("-", ""):
        return None
    ua = user_agent.lower()
    if "cubot" in ua:   # Android phone brand that would trip the generic "bot" rule
        return None
    for category, name, regex in BOT_UA_REGEX:
        if regex.search(user_agent):
            return category, name
    return None


# =============================================================================
# LOG PARSING
# =============================================================================

# Combined nginx log format, with optional trailing fields:
#   '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
#    "$http_referer" "$http_user_agent"' + optional '"$http_host"' + optional
#    '"$http_accept_language" "$http_sec_fetch_mode"' (see README, "Extended log format").
# The request is captured raw so that garbage/TLS/binary request lines are kept and counted.
NGINX_LOG_PATTERN = re.compile(
    r'(?P<ip>[\d.:a-fA-F]+)\s+-\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)\s+'
    r'"(?P<referer>(?:[^"\\]|\\.)*)"\s+'
    r'"(?P<user_agent>(?:[^"\\]|\\.)*)"'
    r'(?:\s+"(?P<host>(?:[^"\\]|\\.)*)")?'
    r'(?:\s+"(?P<accept_language>(?:[^"\\]|\\.)*)")?'
    r'(?:\s+"(?P<sec_fetch_mode>(?:[^"\\]|\\.)*)")?'
)

REQUEST_LINE_RE = re.compile(r'^([A-Z]{3,10})\s+(\S+)\s+(HTTP/\d(?:\.\d)?)$')


def parse_timestamp(ts_str: str) -> datetime:
    """Parse nginx timestamp format: 24/Dec/2024:10:15:30 +0000"""
    ts_clean = ts_str.split()[0] if ' ' in ts_str else ts_str
    return datetime.strptime(ts_clean, "%d/%b/%Y:%H:%M:%S")


def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parse a single nginx log line. Malformed request lines are kept and flagged."""
    match = NGINX_LOG_PATTERN.match(line)
    if not match:
        return None

    try:
        request = match.group("request")
        req_match = REQUEST_LINE_RE.match(request)
        if req_match:
            method, path, protocol = req_match.groups()
            malformed = False
        else:
            method, path, protocol = "MALFORMED", request[:80] or "-", "-"
            malformed = True

        size = match.group("size")
        return LogEntry(
            ip=match.group("ip"),
            timestamp=parse_timestamp(match.group("timestamp")),
            method=method,
            path=path,
            protocol=protocol,
            status=int(match.group("status")),
            size=int(size) if size.isdigit() else 0,
            referer=match.group("referer") or "-",
            user_agent=match.group("user_agent") or "-",
            host=match.group("host") or "-",
            accept_language=match.group("accept_language"),
            sec_fetch_mode=match.group("sec_fetch_mode"),
            malformed=malformed,
        )
    except (ValueError, AttributeError):
        return None


def _open_log(log_file: Path):
    if str(log_file).endswith('.gz'):
        return gzip.open(log_file, 'rt', encoding='utf-8', errors='replace')
    return open(log_file, 'r', encoding='utf-8', errors='replace')


def read_log_file(log_path: str, target_date: date) -> list[LogEntry]:
    """Read and parse the log and its rotated siblings, keeping entries for target_date."""
    entries: list[LogEntry] = []
    path = Path(log_path)

    log_files = [path]
    rotated = path.with_name(path.name + '.1')
    if rotated.exists():
        log_files.append(rotated)
    log_files.extend(sorted(path.parent.glob(f"{path.name}.*.gz")))

    unparsed = 0
    for log_file in log_files:
        if not log_file.exists():
            continue
        try:
            with _open_log(log_file) as f:
                first = f.readline()
                first_entry = parse_log_line(first.strip())
                # Logs are chronological: a file that starts after the target date has nothing for us
                if first_entry and first_entry.timestamp.date() > target_date:
                    continue
                for line in chain([first], f):
                    line = line.strip()
                    if not line:
                        continue
                    entry = parse_log_line(line)
                    if entry is None:
                        unparsed += 1
                        continue
                    if entry.timestamp.date() == target_date:
                        entries.append(entry)
        except (IOError, OSError) as e:
            logger.warning(f"Could not read {log_file}: {e}")

    if unparsed:
        logger.warning(f"{unparsed} log line(s) could not be parsed at all (check log_format)")

    return sorted(entries, key=lambda e: e.timestamp)


# =============================================================================
# ENRICHMENT: GEOIP, ASN, REVERSE DNS
# =============================================================================

class IPEnricher:
    """Caches GeoIP city/ASN lookups and crawler reverse-DNS verification per IP."""

    def __init__(self):
        self.city_reader = None
        self.asn_reader = None
        self._geo_cache: dict[str, dict] = {}
        self._asn_cache: dict[str, tuple[Optional[str], Optional[str]]] = {}
        self._dns_cache: dict[str, str] = {}
        self._dns_lookups = 0

        self.city_db_is_country = False   # GeoLite2-Country (6 MB) works too; it just has no city names

        if GEOIP_AVAILABLE:
            city_candidates = [CONFIG["geoip_db_path"],
                               str(Path(CONFIG["geoip_db_path"]).with_name("GeoLite2-Country.mmdb"))]
            for db_path in city_candidates:
                if Path(db_path).exists():
                    try:
                        self.city_reader = geoip2.database.Reader(db_path)
                        self.city_db_is_country = "country" in self.city_reader.metadata().database_type.lower()
                        break
                    except Exception as e:
                        logger.warning(f"Could not load {db_path}: {e}")

            asn_path = CONFIG["asn_db_path"]
            if Path(asn_path).exists():
                try:
                    self.asn_reader = geoip2.database.Reader(asn_path)
                except Exception as e:
                    logger.warning(f"Could not load {asn_path}: {e}")
            else:
                logger.info("GeoLite2-ASN database not found; datacenter detection disabled "
                            "(add GeoLite2-ASN to EditionIDs in /etc/GeoIP.conf and run geoipupdate)")

    @property
    def asn_available(self) -> bool:
        return self.asn_reader is not None

    def close(self):
        for reader in (self.city_reader, self.asn_reader):
            if reader:
                reader.close()

    def location(self, ip: str) -> dict:
        if ip in self._geo_cache:
            return self._geo_cache[ip]
        loc = {"country": "Unknown", "city": "Unknown"}
        if self.city_reader:
            try:
                if self.city_db_is_country:
                    r = self.city_reader.country(ip)
                    loc = {"country": r.country.name or "Unknown", "city": "Unknown"}
                else:
                    r = self.city_reader.city(ip)
                    loc = {"country": r.country.name or "Unknown", "city": r.city.name or "Unknown"}
            except Exception:
                pass
        self._geo_cache[ip] = loc
        return loc

    def asn(self, ip: str) -> tuple[Optional[str], Optional[str]]:
        """Return (asn, organisation) or (None, None)."""
        if ip in self._asn_cache:
            return self._asn_cache[ip]
        result: tuple[Optional[str], Optional[str]] = (None, None)
        if self.asn_reader:
            try:
                r = self.asn_reader.asn(ip)
                result = (f"AS{r.autonomous_system_number}", r.autonomous_system_organization or "")
            except Exception:
                pass
        self._asn_cache[ip] = result
        return result

    @staticmethod
    def is_datacenter_org(org: Optional[str]) -> bool:
        if not org:
            return False
        o = org.lower()
        if any(k in o for k in DATACENTER_ASN_EXCLUDE):
            return False
        return any(k in o for k in DATACENTER_ASN_KEYWORDS)

    def verify_crawler(self, ip: str, bot_name: str) -> str:
        """Reverse-DNS + forward-confirm a claimed crawler. Returns verified|impostor|unknown."""
        suffixes = CRAWLER_DNS_SUFFIXES.get(bot_name)
        if not suffixes or not CONFIG["verify_crawler_dns"]:
            return "unknown"
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        if self._dns_lookups >= CONFIG["max_dns_lookups"]:
            return "unknown"
        self._dns_lookups += 1

        result = "unknown"
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(CONFIG["dns_timeout_seconds"])
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            if hostname.endswith(suffixes):
                forward_ips = socket.gethostbyname_ex(hostname)[2]
                result = "verified" if ip in forward_ips else "impostor"
            else:
                result = "impostor"
        except socket.herror:
            # No PTR record at all: genuine crawlers from these operators always have one
            result = "impostor"
        except (socket.gaierror, socket.timeout, OSError):
            result = "unknown"
        finally:
            socket.setdefaulttimeout(old_timeout)

        self._dns_cache[ip] = result
        return result


def is_ip_literal(host: str) -> bool:
    """True if a Host header value is an IP address (optionally with a port)."""
    h = host.strip()
    if h.startswith("["):                 # [2001:db8::1]:443
        h = h[1:].split("]", 1)[0]
    elif h.count(":") == 1:               # 203.0.113.5:443
        h = h.split(":", 1)[0]
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


# =============================================================================
# SESSION CLASSIFICATION
# =============================================================================

def build_sessions(entries: list[LogEntry]) -> dict[str, list[VisitorSession]]:
    """Group log entries into sessions keyed by (IP, user agent).

    Keying on the user agent as well as the IP keeps a curl check and a browser visit from the
    same address apart, and keeps a scanner that rotates user agents from being merged with a
    real visitor behind the same NAT.
    """
    sessions_by_ip: dict[str, list[VisitorSession]] = defaultdict(list)
    current: dict[tuple[str, str], VisitorSession] = {}
    timeout = timedelta(minutes=CONFIG["session_timeout_minutes"])

    for entry in entries:
        key = (entry.ip, entry.user_agent)
        session = current.get(key)
        if session and (entry.timestamp - session.last_seen) < timeout:
            session.add_request(entry)
        else:
            session = VisitorSession(entry.ip, entry.timestamp)
            session.add_request(entry)
            sessions_by_ip[entry.ip].append(session)
            current[key] = session

    return sessions_by_ip


def _interval_regularity(timestamps: list[datetime]) -> Optional[float]:
    """Coefficient of variation of inter-request intervals (low = machine-like)."""
    if len(timestamps) < 6:
        return None
    gaps = [(b - a).total_seconds() for a, b in zip(timestamps, timestamps[1:])]
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return None
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    return (var ** 0.5) / mean


def classify_session(session: VisitorSession, enricher: IPEnricher,
                     ip_ua_count: int = 1, ip_probed: bool = False) -> None:
    """Fill in verdict, score, reasons and bot category/name on the session.

    ip_ua_count is how many distinct user agents this IP used today; ip_probed is whether any
    session from this IP today sent probe paths, malformed or proxy-style requests.
    """
    reasons: list[str] = []
    ua = session.primary_user_agent
    browser_ua = looks_like_browser(ua)

    # --- identity signals ----------------------------------------------------
    ua_match = match_bot_user_agent(ua)
    if ua_match:
        reasons.append("ua_bot")
        session.bot_category, session.bot_name = ua_match
        if session.bot_category == "search":
            dns_result = enricher.verify_crawler(session.ip, session.bot_name)
            if dns_result == "impostor":
                reasons.append("impostor_crawler")
                session.bot_category = "impostor"
                session.bot_name = f"Fake {session.bot_name}"
    elif ua in ("-", "") or len(ua) < 8:
        reasons.append("ua_missing")
    elif not browser_ua:
        reasons.append("ua_not_browser")

    # --- request-content signals --------------------------------------------
    if session.probe_paths:
        reasons.append("probe_path")
    if session.malformed:
        reasons.append("malformed_request")
    if session.absolute_uri:
        reasons.append("absolute_uri")
    if any(m not in BROWSER_METHODS and m != "MALFORMED" for m in session.methods):
        reasons.append("odd_method")

    for host in session.hosts:
        if host and host != "-" and is_ip_literal(host):
            reasons.append("ip_host_header")
            break
        if CONFIG["site_hosts"] and host not in ("-", "") and not host_is_ours(host):
            reasons.append("unknown_host")
            break

    real_requests = session.requests - session.malformed
    if real_requests >= 1 and session.error_requests == real_requests and session.static_requests == 0:
        reasons.append("all_errors")
    elif real_requests >= 4 and session.error_requests / real_requests >= 0.75:
        reasons.append("mostly_errors")

    # --- network signals ------------------------------------------------------
    session.asn, session.asn_org = enricher.asn(session.ip)
    if session.asn in SCANNER_ASNS:
        reasons.append("scanner_asn")
    elif enricher.is_datacenter_org(session.asn_org):
        reasons.append("datacenter_asn")

    # --- behavioural signals ------------------------------------------------
    if not ua_match and obsolete_browser(ua):
        reasons.append("obsolete_browser")

    if session.page_request_count >= 2 and session.static_requests == 0:
        reasons.append("no_assets")
    elif session.page_request_count == 1 and session.static_requests == 0:
        reasons.append("single_html_only")
    elif session.page_request_count == 0 and session.static_requests > 0:
        reasons.append("assets_only")
    elif session.static_requests > 0 and session.render_asset_requests == 0:
        reasons.append("images_only")

    if len(session.pages) >= 3 and session.page_requests_with_referer == 0:
        reasons.append("no_referer_multi_page")

    # A person cannot open more than ~30 pages a minute for long; scanners do hundreds.
    if session.non_static_requests > 10 and session.non_static_per_minute > 30:
        reasons.append("high_request_rate")

    if len(session.pages) > 30:
        reasons.append("excessive_page_depth")

    if ip_ua_count >= 3:
        reasons.append("ip_ua_rotation")

    if ip_probed and not session.probe_paths and not session.malformed:
        reasons.append("ip_also_probed")

    if session.requests >= 1 and set(session.methods) == {"HEAD"}:
        reasons.append("head_only")

    if session.technical_endpoint:
        reasons.append("technical_endpoint")

    cv = _interval_regularity(session.timestamps)
    if cv is not None and cv < 0.15 and session.duration_seconds > 30:
        reasons.append("consistent_timing")

    # Extended-format header signals (only when the header was logged at all)
    if browser_ua and session.accept_language_seen is False:
        reasons.append("no_accept_language")
    if browser_ua and session.sec_fetch_seen is False:
        reasons.append("no_sec_fetch")

    # --- decision ------------------------------------------------------------
    weights = dict(SIGNAL_WEIGHTS)
    if not CONFIG["datacenter_is_decisive"]:
        weights["datacenter_asn"] = 2
    score = sum(weights[r] for r in reasons)
    strong_hit = any(weights[r] >= STRONG for r in reasons)

    # Positive evidence of a real browser: it fired the beacon, it pulled in the page's CSS/JS, or it
    # navigated between our own pages sending a same-site Referer a few seconds after arriving
    # (assets are cached for 30 days on this site, so a returning visitor may request HTML only).
    browser_evidence = session.beacon or (
        browser_ua and session.page_request_count > 0
        and (session.render_asset_requests >= CONFIG["min_render_assets"] or session.internal_nav_requests > 0)
    )

    if strong_hit or (score >= BOT_SCORE_THRESHOLD and not session.beacon):
        verdict = "bot"
    elif browser_evidence:
        verdict = "human"
    else:
        verdict = "unverified"

    if verdict == "bot" and session.bot_category is None:
        if "probe_path" in reasons or "malformed_request" in reasons or "ip_host_header" in reasons \
                or "absolute_uri" in reasons or "odd_method" in reasons:
            session.bot_category, session.bot_name = "probe", "Probe with browser/blank UA"
        elif "scanner_asn" in reasons:
            session.bot_category, session.bot_name = "scanner", SCANNER_ASNS[session.asn]
        elif "datacenter_asn" in reasons:
            session.bot_category, session.bot_name = "datacenter", "Datacenter IP"
        elif "ua_missing" in reasons:
            session.bot_category, session.bot_name = "tool", "No user agent"
        else:
            session.bot_category, session.bot_name = "behavioural", "Browser UA, bot behaviour"

    session.verdict = verdict
    session.score = score
    session.reasons = reasons


# =============================================================================
# ANALYTICS
# =============================================================================

def parse_device_info(user_agent: str) -> dict:
    """Parse a user agent string for device, browser and OS information."""
    if USER_AGENTS_AVAILABLE:
        ua = parse_user_agent(user_agent)
        if ua.is_mobile:
            device = "Mobile"
        elif ua.is_tablet:
            device = "Tablet"
        elif ua.is_pc:
            device = "Desktop"
        else:
            device = "Unknown"

        browser_family = ua.browser.family or "Unknown"
        browser_version = ua.browser.version_string or ""
        if browser_version:
            parts = browser_version.split('.')
            browser_display = f"{browser_family} {'.'.join(parts[:2]) if len(parts) >= 2 else parts[0]}"
        else:
            browser_display = browser_family

        os_family = ua.os.family or "Unknown"
        os_display = f"{os_family} {ua.os.version_string}" if ua.os.version_string else os_family
        return {"browser": browser_display, "browser_family": browser_family,
                "os": os_display, "os_family": os_family, "device": device}

    # Fallback: basic string matching
    ua = user_agent
    device = "Desktop"
    if "Mobile" in ua or "Android" in ua:
        device = "Mobile"
    elif "iPad" in ua or "Tablet" in ua:
        device = "Tablet"

    browser = "Unknown"
    for needle, name in (("Edg/", "Edge"), ("OPR/", "Opera"), ("SamsungBrowser", "Samsung Internet"),
                         ("Firefox", "Firefox"), ("Chrome", "Chrome"), ("Safari", "Safari")):
        if needle in ua:
            browser = name
            break

    os_name = "Unknown"
    for needle, name in (("Windows", "Windows"), ("Android", "Android"), ("iPhone", "iOS"),
                         ("iPad", "iOS"), ("Mac OS X", "Mac OS X"), ("CrOS", "Chrome OS"), ("Linux", "Linux")):
        if needle in ua:
            os_name = name
            break

    return {"browser": browser, "browser_family": browser, "os": os_name, "os_family": os_name, "device": device}


def detect_anomalies(analytics: dict, sessions_by_ip: dict, history: Optional[dict] = None) -> list[dict]:
    """Detect anomalous activity patterns and generate alerts.

    With a baseline (see history_context) the volume-type alerts are relative: a day of scanning
    that looks like every other day is not an alert, a day at twice the usual level is.
    """
    alerts = []
    s = analytics["summary"]

    def limit(threshold_key: str, baseline_key: str) -> tuple[float, str]:
        fixed = ALERT_THRESHOLDS[threshold_key]
        if history:
            relative = ALERT_THRESHOLDS["baseline_multiplier"] * history["avg"].get(baseline_key, 0)
            if relative > fixed:
                return relative, f"{relative:.0f}, {ALERT_THRESHOLDS['baseline_multiplier']:g}x the {history['days']}-day average"
        return fixed, str(fixed)

    # 1. High volume of probe requests
    probe_limit, probe_limit_text = limit("suspicious_requests", "probe_requests")
    probe_spike_day = s["probe_requests"] > probe_limit
    if probe_spike_day:
        alerts.append({
            "severity": "HIGH",
            "type": "suspicious_volume",
            "message": f"{s['probe_requests']} probe/attack requests detected (threshold: {probe_limit_text})",
            "details": f"Top patterns: {', '.join(list(analytics['suspicious_requests'].keys())[:3])}"
        })

    # 2. Single IP making excessive requests
    max_requests_per_ip, worst_offender_ip = 0, None
    for ip, sessions in sessions_by_ip.items():
        total_requests = sum(session.requests for session in sessions)
        if total_requests > max_requests_per_ip:
            max_requests_per_ip, worst_offender_ip = total_requests, ip
    ip_limit, ip_limit_text = limit("single_ip_requests", "max_ip_requests")
    if max_requests_per_ip > ip_limit:
        alerts.append({
            "severity": "HIGH",
            "type": "single_ip_abuse",
            "message": f"IP {worst_offender_ip} made {max_requests_per_ip} requests (threshold: {ip_limit_text})",
            "details": "Consider blocking or rate-limiting this IP"
        })

    # 3. Real people hitting errors (scanner 404s are background noise and are not alerted on)
    if s["human_requests"] >= ALERT_THRESHOLDS["human_error_min_requests"]:
        error_percentage = s["human_error_requests"] / s["human_requests"] * 100
        if error_percentage > ALERT_THRESHOLDS["human_error_percentage"]:
            alerts.append({
                "severity": "MEDIUM",
                "type": "human_error_rate",
                "message": f"{error_percentage:.1f}% of verified-human requests failed (threshold: {ALERT_THRESHOLDS['human_error_percentage']}%)",
                "details": f"{s['human_error_requests']} of {s['human_requests']} human requests got 4xx/5xx: check for broken links"
            })

    # 4. Spike in a specific attack pattern (only worth flagging on a day that is itself unusual)
    for pattern, count in analytics["suspicious_requests"].items():
        if count > ALERT_THRESHOLDS["suspicious_spike"] and (probe_spike_day or not history):
            alerts.append({
                "severity": "HIGH",
                "type": "attack_pattern_spike",
                "message": f"Spike detected: '{pattern}' accessed {count} times (threshold: {ALERT_THRESHOLDS['suspicious_spike']})",
                "details": "This could indicate an active attack or aggressive scanning"
            })

    # 5. Server errors (5xx)
    server_errors = sum(count for status, count in analytics["status_codes"].items() if status >= 500)
    if server_errors > ALERT_THRESHOLDS["server_errors"]:
        alerts.append({
            "severity": "HIGH",
            "type": "server_errors",
            "message": f"{server_errors} server errors (5xx) detected",
            "details": "Could indicate server overload, misconfiguration, or DDoS attempt"
        })

    # 6. Fake search crawlers
    impostors = analytics["bot_categories"].get("impostor", 0)
    impostor_limit = ALERT_THRESHOLDS["baseline_multiplier"] * history["avg"].get("impostor_sessions", 0) if history else 0
    if impostors and impostors > impostor_limit:
        alerts.append({
            "severity": "MEDIUM",
            "type": "impostor_crawlers",
            "message": f"{impostors} session(s) claimed to be a search engine crawler but failed reverse-DNS verification",
            "details": "Spoofed Googlebot/Bingbot UAs are used to bypass bot blocks; safe to block these IPs"
        })

    return alerts


def generate_analytics(entries: list[LogEntry], target_date: date, history: Optional[dict] = None) -> dict:
    """Generate comprehensive analytics from log entries"""
    enricher = IPEnricher()

    sessions_by_ip = build_sessions(entries)
    all_sessions = [s for sessions in sessions_by_ip.values() for s in sessions]
    ua_count_by_ip = {ip: len({s.primary_user_agent for s in sessions}) for ip, sessions in sessions_by_ip.items()}
    probed_ips = {ip for ip, sessions in sessions_by_ip.items()
                  if any(s.probe_paths or s.malformed or s.absolute_uri for s in sessions)}

    for session in all_sessions:
        classify_session(session, enricher, ua_count_by_ip[session.ip], session.ip in probed_ips)
        loc = enricher.location(session.ip)
        session.country, session.city = loc["country"], loc["city"]

    human_sessions = [s for s in all_sessions if s.verdict == "human"]
    unverified_sessions = [s for s in all_sessions if s.verdict == "unverified"]
    bot_sessions = [s for s in all_sessions if s.verdict == "bot"]

    def req(sessions):
        return sum(s.requests for s in sessions)

    # ---- reasons & categories ---------------------------------------------
    bot_reasons = Counter()
    for s in bot_sessions:
        for r in s.reasons:
            bot_reasons[r] += 1
    unverified_reasons = Counter()
    for s in unverified_sessions:
        for r in s.reasons:
            unverified_reasons[r] += 1

    bot_categories = Counter(s.bot_category for s in bot_sessions)
    bot_names = Counter(s.bot_name for s in bot_sessions)

    # ---- locations: humans vs bots ----------------------------------------
    def location_counters(sessions):
        countries, cities = Counter(), Counter()
        seen = set()
        for s in sessions:
            if s.ip in seen:
                continue
            seen.add(s.ip)
            countries[s.country] += 1
            cities[f"{s.city}, {s.country}"] += 1
        return countries, cities

    human_countries, human_cities = location_counters(human_sessions)
    bot_countries, _ = location_counters(bot_sessions + unverified_sessions)

    # ---- ASN / networks ---------------------------------------------------
    bot_networks = Counter()
    for s in bot_sessions + unverified_sessions:
        if s.asn_org:
            bot_networks[f"{s.asn_org} ({s.asn})"] += 1

    # ---- pages ------------------------------------------------------------
    human_ips = {s.ip for s in human_sessions}
    human_page_views = Counter()
    for s in human_sessions:
        for p in s.pages:
            human_page_views[p] += 1

    all_page_views = Counter()
    suspicious_requests = Counter()
    for entry in entries:
        if entry.malformed:
            suspicious_requests["<malformed request line>"] += 1
            continue
        clean_path = entry.path.split('?', 1)[0]
        if is_probe_request(clean_path, entry.status):
            suspicious_requests[clean_path] += 1
        elif (not is_static_resource(clean_path) and clean_path != CONFIG["beacon_path"]
              and not is_neutral_path(clean_path)):
            all_page_views[clean_path] += 1

    # ---- devices / browsers (human sessions only) ---------------------------
    devices, browsers, browser_families, operating_systems, os_families = (Counter() for _ in range(5))
    for s in human_sessions:
        info = parse_device_info(s.primary_user_agent)
        devices[info["device"]] += 1
        browsers[info["browser"]] += 1
        browser_families[info["browser_family"]] += 1
        operating_systems[info["os"]] += 1
        os_families[info["os_family"]] += 1

    # ---- referrers (human sessions, external only) -------------------------
    referrers = Counter()
    for entry in entries:
        if entry.ip not in human_ips or entry.referer == "-" or entry.malformed:
            continue
        try:
            ref_domain = urlparse(entry.referer).netloc.lower()
        except Exception:
            continue
        if not ref_domain or host_is_ours(ref_domain) or ref_domain == entry.host.lower():
            continue
        referrers[ref_domain] += 1

    # ---- hourly traffic --------------------------------------------------
    hourly_total, hourly_human = Counter(), Counter()
    for s in all_sessions:
        for ts in s.timestamps:
            hourly_total[ts.hour] += 1
            if s.verdict == "human":
                hourly_human[ts.hour] += 1

    # ---- engagement (verified humans only) -----------------------------
    human_durations = [s.duration_seconds for s in human_sessions]
    avg_duration = sum(human_durations) / len(human_durations) if human_durations else 0
    human_pages = [len(s.pages) for s in human_sessions]
    avg_pages = sum(human_pages) / len(human_pages) if human_pages else 0

    # ---- per-host breakdown (three sites share this log) ----------------------
    host_breakdown: dict[str, Counter] = defaultdict(Counter)
    for s in all_sessions:
        for host, count in s.host_counts.items():
            host_breakdown[host]["total"] += count
            host_breakdown[host][s.verdict] += count
    host_breakdown = dict(sorted(host_breakdown.items(), key=lambda kv: -kv[1]["total"]))

    # ---- misc -----------------------------------------------------------
    service_stats = Counter(entry.host for entry in entries)
    status_codes = Counter(entry.status for entry in entries)
    methods = Counter(entry.method for entry in entries)

    # ---- top bot IPs (for blocking) ----------------------------------------
    per_ip: dict[str, dict] = {}
    for s in bot_sessions:
        d = per_ip.setdefault(s.ip, {"requests": 0, "name": s.bot_name, "reasons": Counter(),
                                     "country": s.country, "asn_org": s.asn_org or ""})
        d["requests"] += s.requests
        d["reasons"].update(s.reasons)
    top_bot_ips = sorted(per_ip.items(), key=lambda kv: kv[1]["requests"], reverse=True)[:10]

    # ---- human session detail (small numbers, so list them) ------------------
    human_detail = []
    for s in sorted(human_sessions, key=lambda x: x.first_seen):
        human_detail.append({
            "time": s.first_seen.strftime("%H:%M"),
            "ip": s.ip,
            "location": f"{s.city}, {s.country}",
            "requests": s.requests,
            "pages": s.pages[:6],
            "duration": s.duration_seconds,
            "browser": parse_device_info(s.primary_user_agent)["browser"],
            "beacon": s.beacon,
        })

    enricher.close()

    total_requests = len(entries)
    analytics = {
        "date": target_date.isoformat(),
        "summary": {
            "total_requests": total_requests,
            "unique_ips": len(sessions_by_ip),
            "total_sessions": len(all_sessions),
            "human_sessions": len(human_sessions),
            "unverified_sessions": len(unverified_sessions),
            "bot_sessions": len(bot_sessions),
            "human_requests": req(human_sessions),
            "unverified_requests": req(unverified_sessions),
            "bot_requests": req(bot_sessions),
            "human_ips": len(human_ips),
            "human_error_requests": sum(s.error_requests for s in human_sessions),
            "max_ip_requests": max((sum(x.requests for x in v) for v in sessions_by_ip.values()), default=0),
            "impostor_sessions": bot_categories.get("impostor", 0),
            "probe_requests": sum(suspicious_requests.values()),
            "malformed_requests": sum(1 for e in entries if e.malformed),
            "total_bandwidth_mb": round(sum(s.total_bytes for s in all_sessions) / (1024 * 1024), 2),
            "human_bandwidth_mb": round(sum(s.total_bytes for s in human_sessions) / (1024 * 1024), 2),
            "avg_session_duration_seconds": round(avg_duration),
            "avg_pages_per_session": round(avg_pages, 1),
            "asn_available": enricher.asn_available,
            "beacon_hits": sum(1 for s in all_sessions if s.beacon),
        },
        "bot_categories": dict(bot_categories.most_common()),
        "bot_names": dict(bot_names.most_common(15)),
        "bot_reasons": dict(bot_reasons.most_common()),
        "unverified_reasons": dict(unverified_reasons.most_common()),
        "top_pages_human": dict(human_page_views.most_common(15)),
        "top_pages_all": dict(all_page_views.most_common(15)),
        "suspicious_requests": dict(suspicious_requests.most_common(15)),
        "human_countries": dict(human_countries.most_common(10)),
        "human_cities": dict(human_cities.most_common(10)),
        "bot_countries": dict(bot_countries.most_common(10)),
        "bot_networks": dict(bot_networks.most_common(10)),
        "devices": dict(devices),
        "browsers": dict(browsers.most_common(10)),
        "browser_families": dict(browser_families.most_common(8)),
        "operating_systems": dict(operating_systems.most_common(10)),
        "os_families": dict(os_families.most_common(8)),
        "referrers": dict(referrers.most_common(10)),
        "hourly_traffic": dict(sorted(hourly_total.items())),
        "hourly_human": dict(sorted(hourly_human.items())),
        "services": dict(service_stats.most_common(10)),
        "host_breakdown": {h: dict(c) for h, c in host_breakdown.items()},
        "status_codes": dict(sorted(status_codes.items())),
        "methods": dict(methods.most_common()),
        "top_bot_ips": [(ip, {**d, "reasons": [r for r, _ in d["reasons"].most_common(3)]}) for ip, d in top_bot_ips],
        "human_detail": human_detail,
    }

    analytics["security_alerts"] = detect_anomalies(analytics, sessions_by_ip, history)
    analytics["_sessions_by_ip"] = sessions_by_ip   # not serialisable; popped by main()
    return analytics


# =============================================================================
# HISTORY (rolling baseline)
# =============================================================================

HISTORY_FIELDS = ("total_requests", "unique_ips", "bot_sessions", "unverified_sessions",
                  "human_sessions", "human_requests", "probe_requests", "max_ip_requests",
                  "impostor_sessions")


def load_history(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def save_history(path: str, analytics: dict) -> None:
    """Append today's summary, replacing any existing row for the same date."""
    rows = [r for r in load_history(path) if r.get("date") != analytics["date"]]
    rows.append({"date": analytics["date"], **{k: analytics["summary"][k] for k in HISTORY_FIELDS}})
    rows.sort(key=lambda r: r["date"])
    rows = rows[-90:]
    try:
        Path(path).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    except OSError as e:
        logger.warning(f"Could not write history file {path}: {e}")


def history_context(rows: list[dict], analytics: dict) -> Optional[dict]:
    """Average of the previous N days (excluding today) for comparison."""
    today = analytics["date"]
    prior = [r for r in rows if r.get("date") != today][-CONFIG["history_days"]:]
    if not prior:
        return None
    avg = {k: sum(r.get(k, 0) for r in prior) / len(prior) for k in HISTORY_FIELDS}
    return {"days": len(prior), "avg": avg, "first_date": prior[0]["date"], "last_date": prior[-1]["date"]}


# =============================================================================
# REPORT GENERATION
# =============================================================================

def format_duration(seconds: int) -> str:
    """Format seconds into human-readable duration"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    return f"{hours}h {minutes}m"


def _pct(part: int, whole: int) -> str:
    return f"{(part / whole * 100) if whole else 0:.1f}%"


def _section(title: str) -> str:
    return f"\n{title}\n───────────────────────────────────────────────────────────────────\n"


def generate_text_report(analytics: dict, history: Optional[dict] = None) -> str:
    """Generate a human-readable text report"""
    s = analytics["summary"]

    report = f"""
═══════════════════════════════════════════════════════════════════
               NGINX ANALYTICS DIGEST - {analytics['date']}
═══════════════════════════════════════════════════════════════════
"""

    if analytics.get("security_alerts"):
        report += """
╔═══════════════════════════════════════════════════════════════════╗
║                      SECURITY ALERTS                              ║
╚═══════════════════════════════════════════════════════════════════╝
"""
        for alert in analytics["security_alerts"]:
            severity_symbol = "🔴" if alert["severity"] == "HIGH" else "🟡"
            report += f"\n[{alert['severity']}] {severity_symbol} {alert['type'].upper()}\n"
            report += f"  {alert['message']}\n"
            report += f"  → {alert['details']}\n"
        report += "\n"

    report += _section("TRAFFIC CLASSIFICATION")
    report += f"""  Requests:  {s['total_requests']:>6} total
             {s['bot_requests']:>6} bot         ({_pct(s['bot_requests'], s['total_requests'])})
             {s['unverified_requests']:>6} unverified  ({_pct(s['unverified_requests'], s['total_requests'])})
             {s['human_requests']:>6} human       ({_pct(s['human_requests'], s['total_requests'])})

  Sessions:  {s['total_sessions']:>6} total from {s['unique_ips']} unique IPs
             {s['bot_sessions']:>6} bot         ({_pct(s['bot_sessions'], s['total_sessions'])})
             {s['unverified_sessions']:>6} unverified  ({_pct(s['unverified_sessions'], s['total_sessions'])})
             {s['human_sessions']:>6} human       ({_pct(s['human_sessions'], s['total_sessions'])})  from {s['human_ips']} IP(s)

  Probe/attack requests: {s['probe_requests']}   Malformed request lines: {s['malformed_requests']}
  Bandwidth: {s['total_bandwidth_mb']:.2f} MB total, {s['human_bandwidth_mb']:.2f} MB to humans
"""
    notes = []
    if not s["asn_available"]:
        notes.append("GeoLite2-ASN database not installed: datacenter IPs cannot be flagged, so 'unverified' is inflated.")
    if s["beacon_hits"] == 0 and CONFIG["beacon_path"]:
        notes.append(f"No JS beacon hits ({CONFIG['beacon_path']}); humans are verified by asset loads only.")
    if history:
        a = history["avg"]
        notes.append(f"{history['days']}-day baseline ({history['first_date']} to {history['last_date']}): "
                     f"{a['total_requests']:.0f} requests/day, {a['human_sessions']:.1f} human sessions/day, "
                     f"{a['probe_requests']:.0f} probe requests/day.")
    for n in notes:
        report += f"  ℹ {n}\n"

    report += _section("HOW TO READ THIS")
    report += ("  HUMAN      = browser UA that also loaded the page's CSS/JS, navigated to another page\n"
               "               with a same-site Referer after a few seconds, or fired the JS beacon.\n"
               "  BOT        = at least one decisive signal (bot/tool UA, probe path, malformed request,\n"
               "               IP-address Host header, datacenter network, all-error session, fake crawler)\n"
               "               or several behavioural red flags.\n"
               "  UNVERIFIED = browser-like UA with nothing to back it up (typically one HTML fetch).\n"
               "               On a site this size these are almost always bots wearing a browser UA.\n")

    # ---- humans -------------------------------------------------------------
    report += _section("VERIFIED HUMAN SESSIONS")
    if analytics["human_detail"]:
        report += f"  Avg session length: {format_duration(s['avg_session_duration_seconds'])}   Avg pages/session: {s['avg_pages_per_session']}\n\n"
        for h in analytics["human_detail"][:25]:
            beacon = " [beacon]" if h["beacon"] else ""
            pages = ", ".join(h["pages"]) or "-"
            report += (f"  {h['time']}  {h['ip']:<15} {h['location']:<28} {h['browser']:<16} "
                       f"{h['requests']:>3} req  {format_duration(h['duration']):>7}{beacon}\n"
                       f"         pages: {pages}\n")
        if len(analytics["human_detail"]) > 25:
            report += f"  ... and {len(analytics['human_detail']) - 25} more\n"
    else:
        report += "  None. No session showed evidence of a real browser today.\n"

    if analytics["top_pages_human"]:
        report += _section("TOP PAGES (Verified humans)")
        for page, count in list(analytics["top_pages_human"].items())[:10]:
            report += f"  {count:>5}  {page}\n"

    if analytics["human_countries"]:
        report += _section("HUMAN VISITOR COUNTRIES")
        for location, count in analytics["human_countries"].items():
            report += f"  {count:>5}  {location}\n"

    if analytics["human_cities"]:
        report += _section("HUMAN VISITOR CITIES")
        for location, count in list(analytics["human_cities"].items())[:8]:
            report += f"  {count:>5}  {location}\n"

    if analytics["devices"]:
        report += _section("DEVICES (Verified humans)")
        for device, count in analytics["devices"].items():
            report += f"  {device:<12} {count:>5} ({_pct(count, s['human_sessions'])})\n"

    if analytics["browser_families"]:
        report += _section("BROWSERS (Verified humans)")
        for browser, count in list(analytics["browsers"].items())[:8]:
            report += f"  {count:>5}  {browser}\n"

    if analytics["os_families"]:
        report += _section("OPERATING SYSTEMS (Verified humans)")
        for os_name, count in list(analytics["operating_systems"].items())[:8]:
            report += f"  {count:>5}  {os_name}\n"

    if analytics["referrers"]:
        report += _section("EXTERNAL REFERRERS (Verified humans)")
        for referrer, count in list(analytics["referrers"].items())[:8]:
            report += f"  {count:>5}  {referrer}\n"

    # ---- bots ---------------------------------------------------------------
    if analytics["bot_categories"]:
        report += _section("BOT SESSIONS BY CATEGORY")
        for cat, count in analytics["bot_categories"].items():
            report += f"  {count:>5}  {CATEGORY_LABELS.get(cat, cat)}\n"

    if analytics["bot_names"]:
        report += _section("TOP BOTS (by session)")
        for name, count in analytics["bot_names"].items():
            report += f"  {count:>5}  {name}\n"

    if analytics["bot_reasons"]:
        report += _section("BOT DETECTION SIGNALS (sessions carrying each signal)")
        for reason, count in analytics["bot_reasons"].items():
            report += f"  {count:>5}  {SIGNAL_LABELS.get(reason, reason)}\n"

    if analytics["unverified_reasons"] or s["unverified_sessions"]:
        report += _section("UNVERIFIED SESSIONS: why they were not counted as human")
        if analytics["unverified_reasons"]:
            for reason, count in analytics["unverified_reasons"].items():
                report += f"  {count:>5}  {SIGNAL_LABELS.get(reason, reason)}\n"
        else:
            report += "  Browser-like UA but no asset requests and no other signals.\n"

    if analytics["suspicious_requests"]:
        report += _section("PROBE / ATTACK PATHS")
        for page, count in list(analytics["suspicious_requests"].items())[:15]:
            report += f"  {count:>5}  {page}\n"

    if analytics["top_bot_ips"]:
        report += _section("TOP BOT IPs (candidates for blocking)")
        for ip, d in analytics["top_bot_ips"]:
            reasons = ", ".join(SIGNAL_LABELS.get(r, r) for r in d["reasons"])
            org = f" | {d['asn_org']}" if d["asn_org"] else ""
            report += f"  {d['requests']:>5}  {ip:<15} {d['country']:<16} {d['name']}{org}\n          {reasons}\n"

    if analytics["bot_networks"]:
        report += _section("BOT & UNVERIFIED TRAFFIC BY NETWORK (ASN)")
        for network, count in analytics["bot_networks"].items():
            report += f"  {count:>5}  {network}\n"

    if analytics["bot_countries"]:
        report += _section("BOT & UNVERIFIED TRAFFIC BY COUNTRY (unique IPs)")
        for location, count in analytics["bot_countries"].items():
            report += f"  {count:>5}  {location}\n"

    # ---- everything else ----------------------------------------------------
    if analytics["top_pages_all"]:
        report += _section("MOST REQUESTED PAGES (all traffic, excluding probes & assets)")
        for page, count in list(analytics["top_pages_all"].items())[:10]:
            report += f"  {count:>5}  {page}\n"

    if analytics["status_codes"]:
        report += _section("STATUS CODES")
        for code, count in analytics["status_codes"].items():
            label = STATUS_LABELS.get(code, "")
            report += f"  {count:>5}  {code}  {label}\n"

    if analytics["methods"]:
        report += _section("HTTP METHODS")
        for method, count in analytics["methods"].items():
            report += f"  {count:>5}  {method}\n"

    if analytics["host_breakdown"]:
        report += _section("TRAFFIC BY HOST HEADER (requests: total / bot / unverified / human)")
        hosts = analytics["host_breakdown"]
        if list(hosts) == ["-"]:
            report += "  Host header is not logged: add \"$http_host\" to log_format to split traffic per site.\n"
        for host, c in list(hosts.items())[:12]:
            report += (f"  {c.get('total', 0):>6} {c.get('bot', 0):>6} {c.get('unverified', 0):>6} "
                       f"{c.get('human', 0):>6}   {host}\n")

    if analytics["hourly_traffic"]:
        report += _section("HOURLY TRAFFIC (█ all, ▓ human)")
        max_hourly = max(analytics["hourly_traffic"].values()) or 1
        for hour in range(24):
            count = analytics["hourly_traffic"].get(hour, 0)
            human = analytics["hourly_human"].get(hour, 0)
            bar_len = int(count / max_hourly * 30)
            human_len = int(human / max_hourly * 30)
            bar = "▓" * human_len + "█" * (bar_len - human_len)
            report += f"  {hour:02d}:00  {bar} {count}" + (f" ({human} human)" if human else "") + "\n"

    report += "\n═══════════════════════════════════════════════════════════════════\n"
    return report


def dump_sessions(sessions_by_ip: dict[str, list[VisitorSession]], limit: int = 80) -> str:
    """Per-session verdict table for inspecting the classifier."""
    all_sessions = [s for sessions in sessions_by_ip.values() for s in sessions]
    all_sessions.sort(key=lambda s: ({"human": 0, "unverified": 1, "bot": 2}[s.verdict], -s.requests))
    out = [f"{'verdict':<10} {'req':>4} {'ip':<16} {'country':<14} {'who':<28} reasons / sample paths"]
    for s in all_sessions[:limit]:
        who = s.bot_name or (parse_device_info(s.primary_user_agent)["browser"] if looks_like_browser(s.primary_user_agent)
                             else s.primary_user_agent[:26])
        paths = ", ".join((s.probe_paths or s.pages)[:3])[:60]
        out.append(f"{s.verdict:<10} {s.requests:>4} {s.ip:<16} {s.country[:14]:<14} {who[:28]:<28} "
                   f"{','.join(s.reasons) or '-'}  |  {paths}")
        if s.asn_org:
            out.append(f"{'':<10} {'':>4} {'':<16} {'':<14} {'':<28} net: {s.asn_org} ({s.asn})")
    if len(all_sessions) > limit:
        out.append(f"... {len(all_sessions) - limit} more sessions")
    return "\n".join(out)


# =============================================================================
# LLM ANALYSIS
# =============================================================================

def build_llm_prompt(report: str, analytics: dict, history: Optional[dict]) -> str:
    s = analytics["summary"]
    baseline = ""
    if history:
        a = history["avg"]
        baseline = (f"\nBaseline over the previous {history['days']} day(s): "
                    f"{a['total_requests']:.0f} requests/day, {a['bot_sessions']:.0f} bot sessions/day, "
                    f"{a['unverified_sessions']:.0f} unverified sessions/day, {a['human_sessions']:.1f} verified human "
                    f"sessions/day, {a['probe_requests']:.0f} probe requests/day.\n")

    return f"""You are reviewing the daily nginx access-log digest for a small personal developer-portfolio website.

Ground truth about this site: it receives very few genuine human visitors. Nearly all requests come from
internet-wide scanners, vulnerability probes, HTTP libraries and crawlers. The report below classifies every
session into exactly one of three buckets:

  HUMAN      - a browser user agent that also fetched the page's CSS/JS, navigated to another page with
               a same-site Referer a few seconds after arriving, or fired the JS beacon. These are the
               only sessions that represent real people.
  BOT        - a definite automated client: bot/tool user agent, probe/attack paths, malformed request lines,
               an IP address in the Host header, a hosting/cloud network, all-error sessions, a fake search
               crawler, or several behavioural red flags.
  UNVERIFIED - a browser-like user agent with no corroborating evidence, usually a single HTML fetch with
               no assets. On a site like this these are almost always bots spoofing a browser. Treat them as
               probable bots. Never describe them as visitors, readers, or an audience.

Today: {s['total_requests']} requests, {s['bot_sessions']} bot sessions, {s['unverified_sessions']} unverified sessions,
{s['human_sessions']} verified human sessions from {s['human_ips']} IP(s).{baseline}

Rules for your commentary:
- Only the HUMAN bucket describes real people. Do not infer interest, engagement or popularity from bot or
  unverified traffic. If there were zero verified humans, say so plainly and do not soften it.
- Do not restate the numbers back at length; interpret them.
- Be concrete about anything worth blocking (IPs, ASNs, paths) and anything that changed versus the baseline.
- Keep it under 350 words, in a conversational tone, as a colleague reviewing the stats with me.

Here is today's report:

{report}

Please cover, briefly:
1. What real humans (if any) did today: where from, what they looked at, anything notable.
2. What the automated traffic was doing, by category, and whether anything looks like a targeted attack
   rather than background internet noise.
3. Security: probe patterns, alerts, fake crawlers, top offending IPs or networks worth blocking.
4. How today compares with the baseline (if one is given).
5. One or two concrete, actionable suggestions.
If there were no humans at all, a light-hearted line about the lack of visitors is welcome."""


def get_llm_analysis(prompt: str) -> str:
    """Get LLM commentary on the analytics using the llm Python SDK"""
    if not LLM_AVAILABLE:
        return "[LLM analysis unavailable: llm library not installed]"
    try:
        model = llm.get_model(CONFIG["llm_model"])
        response = model.prompt(prompt)
        if response and response.text():
            return response.text().strip()
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

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Nginx analytics daily digest")
    p.add_argument("--date", help="Date to analyse (YYYY-MM-DD). Default: yesterday")
    p.add_argument("--log", help=f"Access log path. Default: {CONFIG['log_path']}")
    p.add_argument("--stdout", action="store_true", help="Print the report instead of emailing it")
    p.add_argument("--no-llm", action="store_true", help="Skip the LLM commentary")
    p.add_argument("--no-history", action="store_true", help="Do not record today's numbers in the history file")
    p.add_argument("--sessions", action="store_true", help="Also print a per-session verdict table (implies --stdout)")
    p.add_argument("--json", action="store_true", help="Print the analytics dict as JSON (implies --stdout)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.sessions or args.json:
        args.stdout = True

    try:
        if args.date:
            target_date = datetime.strptime(args.date, "%Y-%m-%d").date()
        else:
            target_date = (datetime.now() - timedelta(days=1)).date()
        log_path = args.log or CONFIG["log_path"]

        entries = read_log_file(log_path, target_date)
        if not entries:
            logger.warning(f"No log entries found for {target_date}")
            sys.exit(0)
        logger.info(f"Found {len(entries)} log entries for {target_date}")

        # =================================================================
        # STAGE 1: Generate analytics and text report
        # =================================================================
        logger.info("STAGE 1: Generating analytics report")
        history = history_context(load_history(CONFIG["history_path"]), {"date": target_date.isoformat()})
        analytics = generate_analytics(entries, target_date, history)
        sessions_by_ip = analytics.pop("_sessions_by_ip")
        report = generate_text_report(analytics, history)
        if not args.no_history:
            save_history(CONFIG["history_path"], analytics)

        s = analytics["summary"]
        logger.info(f"Classified {s['total_sessions']} sessions: {s['bot_sessions']} bot, "
                    f"{s['unverified_sessions']} unverified, {s['human_sessions']} human")

        if analytics.get("security_alerts"):
            logger.warning(f"Security alerts detected: {len(analytics['security_alerts'])} alert(s)")
            for alert in analytics["security_alerts"]:
                logger.warning(f"[{alert['severity']}] {alert['type']}: {alert['message']}")

        if args.sessions:
            print(dump_sessions(sessions_by_ip))
            print()

        if args.json:
            print(json.dumps(analytics, indent=2, default=str))
            sys.exit(0)

        # =================================================================
        # STAGE 2: Get LLM analysis
        # =================================================================
        llm_analysis = ""
        if not args.no_llm:
            logger.info("STAGE 2: Getting LLM analysis")
            llm_analysis = get_llm_analysis(build_llm_prompt(report, analytics, history))
            if llm_analysis and not llm_analysis.startswith("[LLM analysis"):
                logger.info("LLM analysis completed successfully")
            else:
                logger.warning(f"LLM analysis issue: {llm_analysis}")

        final_report = report
        if llm_analysis and not llm_analysis.startswith("[LLM analysis"):
            final_report += f"""

DeepSeek says...
{llm_analysis}

That's all for today's Nginx analytics digest!
"""

        if args.stdout:
            print(final_report)
            sys.exit(0)

        # =================================================================
        # STAGE 3: Compose and send email
        # =================================================================
        logger.info("STAGE 3: Composing and sending email")
        subject = f"Nginx Digest for {target_date}: {s['human_sessions']} human, {s['bot_sessions']} bot sessions"
        if analytics.get("security_alerts"):
            high_alerts = sum(1 for a in analytics["security_alerts"] if a["severity"] == "HIGH")
            subject = ("🔴 SECURITY ALERT - " if high_alerts else "⚠️ Alert - ") + subject

        if send_email(subject=subject, body=final_report, to_addr=CONFIG["email_to"]):
            logger.info(f"Email sent successfully to {CONFIG['email_to']}")
            sys.exit(0)
        logger.error("Failed to send email")
        sys.exit(1)

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        sys.exit(1)
    except PermissionError as e:
        logger.error(f"Permission denied: {e}")
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
