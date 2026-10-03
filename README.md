# 📊 Nginx Analytics Daily Digest 🍽️ 😋

Parses nginx access logs, classifies every session as **bot / unverified / human** using evidence-based rules, generates visitor analytics with geolocation data, gets LLM commentary, and sends a daily email digest.

```bash
source .venv/bin/activate
```

<br>

---

### 🧪 Running it by hand

```bash
python nginx_digest.py --help
python nginx_digest.py --stdout --no-llm                       # yesterday's email body, printed, no email/LLM
python nginx_digest.py --stdout --full --no-llm                # ...plus the full report the LLM sees
python nginx_digest.py --date 2026-09-14 --sessions --no-llm   # + per-session verdict table
python nginx_digest.py --log /path/to/access.log --json        # raw analytics as JSON
python nginx_digest.py --stdout --no-history                   # don't record the day in digest_history.jsonl
```

`--sessions` is the tool for tuning: it prints one line per session with the verdict, who it was, and every signal that fired, so you can see exactly why something was or wasn't counted as human.

Tests (a fixture log with one session per classifier rule):

```bash
python -m unittest discover -s tests -v
```

<br>

---

### 🕵️ How traffic is classified

Every session (all requests from one **IP + user agent** pair within `session_timeout_minutes`) gets exactly one verdict. Keying on the user agent too means a `curl` check and a browser visit from the same address are judged separately, and a scanner rotating UAs behind the same NAT as a real visitor can't drag the visitor down with it.

| Verdict | Meaning |
|---|---|
| **HUMAN** | Browser user agent **and** one of: the session fetched at least two CSS/JS/font files (including `304`s; images and icons don't count, scanners fetch those); it navigated to another of our own pages with a same-site `Referer` at least 5 s after arriving (form-spam bots do it in 0-3 s); or it fired the JS beacon. The `Referer` route exists because assets are cached for 30 days (`expires 30d`), so a returning visitor can legitimately request HTML only. Only these sessions feed the "visitors", devices, browsers, referrers and top-pages sections. |
| **BOT** | At least one *decisive* signal, or several behavioural ones (see below). |
| **UNVERIFIED** | Browser-like UA with nothing to back it up: typically a single HTML fetch with no assets. On a small site these are almost all bots wearing a browser UA. They are reported separately and the LLM is told to treat them as probable bots. |

Decisive signals (any one makes a session a bot):

- bot / tool / library user agent (≈120 patterns: search engines, AI crawlers, SEO tools, link unfurlers, scanners, `curl`, `python-requests`, `Go-http-client`, headless browsers, ...)
- empty user agent
- any request for a probe path (`/.env`, `wp-login.php`, `xmlrpc.php`, `/.git`, `phpmyadmin`, ... see `PROBE_PATTERNS`) **that the server did not serve**. A pattern-matching path that returned 200/304 is a real page on this site (e.g. `/gf/housing.php`), not a probe; a 301/404 for `/.env` is.
- malformed request line (raw TLS handshakes, binary junk) - these used to be silently dropped by the parser
- `Host` header is the server's IP address, or not one of `SITE_HOSTS`
- proxy-style absolute-URI request, or non-browser method (`PROPFIND`, `CONNECT`, ...)
- every request in the session failed (4xx/5xx) with no assets loaded
- the IP belongs to a hosting/cloud provider, or to a known scanner network such as Shodan, Censys or ONYPHE (needs the ASN database, below; `DATACENTER_ASN_KEYWORDS` and `SCANNER_ASNS` are the lists to extend when a new one shows up in the `--sessions` table)
- claims to be Googlebot/Bingbot/etc. but fails reverse-DNS verification
- browser UA with no `Accept-Language` header (needs the extended log format, below)

Behavioural signals (medium = 2 points, weak = 1; 3 points = bot): pages fetched but never any assets, a single HTML fetch, a browser version nobody uses any more (Chrome/Firefox < 100, IE, Windows 7 and older), HEAD-only, several pages with no `Referer`, more than 30 page requests a minute (assets don't count, one page can pull in dozens), the same IP using 3+ user agents or sending probes elsewhere in the day, robots.txt/sitemap fetches, machine-regular timing.

Weights live in `SIGNAL_WEIGHTS`; `CONFIG["datacenter_is_decisive"]` downgrades the datacenter signal to a medium one if you expect real visitors via commercial VPNs.

<br>

---

### 🎯 Getting more signal (recommended, in order of payoff)

**1. ASN database (5 minutes, biggest win).** Most "unverified" sessions come from AWS, Hetzner, DigitalOcean, Alibaba, OVH, etc. Nobody browses a portfolio site from a datacenter. Add the free GeoLite2-ASN database to `/etc/GeoIP.conf` and update:

```
EditionIDs GeoLite2-City GeoLite2-ASN
```
```bash
sudo geoipupdate
```

The script picks up `/var/lib/GeoIP/GeoLite2-ASN.mmdb` automatically and the report gains a "traffic by network" section. Provider matching is by organisation name (`DATACENTER_ASN_KEYWORDS`); Cloudflare, Fastly and Apple are excluded because iCloud Private Relay and Cloudflare WARP route real people through them.

**2. JS beacon (ground truth for "a browser rendered this").** Only a JavaScript-executing client can request it. It matters more on this site than most: assets are cached for 30 days, so a returning visitor who lands on one page and leaves produces a single HTML request that is indistinguishable from a scanner without it. Add to nginx (inside the main `server` block, before the static-asset `location` so `.gif` caching doesn't swallow it):

```nginx
location = /beacon.gif {
    empty_gif;
    add_header Cache-Control "no-store";
    access_log /var/log/nginx/access.log;   # same log/format as the site
}
```

and before `</body>` on every page:

```html
<script>
  // Traffic beacon: only real browsers run this. Nothing is stored client-side.
  (function () {
    var i = new Image();
    i.src = '/beacon.gif?p=' + encodeURIComponent(location.pathname) + '&t=' + Date.now();
  })();
</script>
```

A session that hits `/beacon.gif` is counted as human unless a decisive bot signal also fired (so a headless Chrome on AWS still shows up as a bot). Path is configurable via `CONFIG["beacon_path"]`.

**3. Extended log format (catches browser-UA spoofers).** Real browsers always send `Accept-Language` and modern ones send `Sec-Fetch-Mode`; most scanners with a fake Chrome UA send neither. The server block does not set `access_log`, so it inherits the default `combined` format from the `http` block of `/etc/nginx/nginx.conf`. Add the `log_format` there, next to the existing `access_log` line, and point that line at it:

```nginx
log_format digest '$remote_addr - $remote_user [$time_local] "$request" '
                  '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                  '"$http_host" "$http_accept_language" "$http_sec_fetch_mode"';
access_log /var/log/nginx/access.log digest;
```

The parser accepts both the current format and this one; the two extra headers are simply optional trailing fields. Reload with `sudo nginx -t && sudo systemctl reload nginx`.

To see every server block that writes to the log (subdomains live in other `sites-enabled` files):

```bash
ls /etc/nginx/sites-enabled/
sudo nginx -T 2>/dev/null | grep -nE '^\s*(server_name|listen|access_log|log_format|root|proxy_pass)'
```

**4. `$http_host` in the log, and `SITE_HOSTS` in `.env`.** The VM currently uses nginx's standard `combined` format, which has no Host field, so the Host-based signals can't fire and traffic for every server block on the box lands in the same numbers. Appending `"$http_host"` to the format (it is the first optional field in the extended format above) fixes both. Then set `SITE_HOSTS=followcrom.com`; subdomains such as `mixtape.followcrom.com` match automatically. Requests with any other `Host` header (a bare IP, `example.com`, ...) are scanner traffic: nothing links to your server by IP.

**5. Baseline.** Each run appends the day's summary to `digest_history.jsonl` (gitignored). After a few days the report and the LLM prompt include a 7-day baseline, so "quiet day" versus "something changed" becomes a real comparison rather than a guess. The probe-volume, single-IP and fake-crawler alerts also become relative once the baseline exists: they fire only when today is more than `baseline_multiplier` (2x) the 7-day average, so the ~6,000 probes a day of ordinary background scanning stop putting a 🔴 in every subject line. Until the first week of history exists the fixed thresholds in `ALERT_THRESHOLDS` apply.

Other sources worth considering later: `fail2ban`/nginx `error.log` for what was already blocked, Google Search Console (the only authoritative count of Google-referred humans), and MaxMind's paid anonymous-IP database if VPN traffic ever matters.

### 📍 MaxMind GeoIP

`geoip2` is just the Python library with no config. You also need the database files from MaxMind. `geoipupdate` is the official tool to download and update them.

The script uses two databases, both free GeoLite2 editions:

| File | Size | Used for |
|---|---|---|
| `GeoLite2-City.mmdb` | ~60 MB | country/city of each IP (`GeoLite2-Country.mmdb`, ~6 MB, also works if space is ever tight) |
| `GeoLite2-ASN.mmdb` | ~8 MB | network owner of each IP: the datacenter/cloud signal, the biggest single accuracy win |

Status on the box (checked 2026-09-16): `GeoLite2-City.mmdb` was present but nine months old, `GeoLite2-ASN.mmdb` was missing, and `geoipupdate` was **not** installed. 15 GB free, so there is no reason not to run both.

1. **Install geoipupdate on the box:**
   ```bash
   sudo apt install geoipupdate
   ```
   If apt asks whether to replace `/etc/GeoIP.conf`, keep the existing one (it has the account ID and licence key; a copy is in this repo's `GeoIP.conf`).

2. **Ask for both editions.** In `/etc/GeoIP.conf`:
   ```
   EditionIDs GeoLite2-City GeoLite2-ASN
   DatabaseDirectory /var/lib/GeoIP
   ```

3. **Download / refresh:**
   ```bash
   sudo geoipupdate -v
   ls -lh /var/lib/GeoIP/
   ```
   The digest picks up `GeoLite2-ASN.mmdb` automatically; the "database not found" log line disappears on the next run.

4. **Automatic updates.** The package installs `geoipupdate.timer` (weekly). Enable it once:
   ```bash
   sudo systemctl enable --now geoipupdate.timer
   ```
   MaxMind refreshes GeoLite twice a week. Datacenter IP ranges churn, so keeping the ASN file fresh matters more than the city data.

5. **Check what you have:**
   ```bash
   ls -lh /var/lib/GeoIP/
   /var/www/digest/dig_venv/bin/python -c "
   import geoip2.database, datetime
   for f in ('GeoLite2-City', 'GeoLite2-ASN'):
       m = geoip2.database.Reader(f'/var/lib/GeoIP/{f}.mmdb').metadata()
       print(m.database_type, datetime.datetime.fromtimestamp(m.build_epoch).date())"
   ```

<br>

---

### 🤖🧠 LLM Setup 👾

This project uses a **project-specific LLM configuration**. This means:

- Fresh model lists (no inherited models from global config)
- Separate API keys
- Independent settings
- Configuration stored in `.llm/` within this project (gitignored)

Set a custom location for the config directory by setting the LLM_USER_PATH environment variable:

`export LLM_USER_PATH=./.llm/`

When you run `llm` commands, it will use this directory for config and keys.

#### Changing the model

The model is set by `CONFIG["llm_model"]` in `nginx_digest.py` (currently `deepseek-flash`).

DeepSeek models are registered in `.llm/extra-openai-models.yaml` through llm's built-in OpenAI-compatible support, not the `llm-deepseek` plugin. That plugin (0.1.6, the latest release) only knows the retired names `deepseek-chat`/`deepseek-reasoner`. Because `.llm/` is gitignored, create or edit this file on the server too:

```yaml
- model_id: deepseek-flash
  model_name: deepseek-flash
  api_base: "https://api.deepseek.com"
  api_key_name: deepseek
- model_id: deepseek-v4-pro
  model_name: deepseek-v4-pro
  api_base: "https://api.deepseek.com"
  api_key_name: deepseek
```

`api_key_name` must match the key name in `.llm/keys.json`. To switch:

1. Add the model to the YAML file if it isn't there.
2. Check that it works: `LLM_USER_PATH=/var/www/digest/.llm llm -m deepseek-v4-pro "Reply with just: OK"`
3. Change `llm_model` in `nginx_digest.py`.
4. Compare the commentary with `python nginx_digest.py --stdout --no-history`.

If the model name is wrong, the script still sends the email, just without the AI commentary, and logs a "model not found" warning in `nginx_digest.log`.

Choosing a model: `deepseek-flash` is enough for this job. The script does the classification and counting, and the AI only comments on the finished report. `deepseek-v4-pro` costs about 4x as much (still only a few dollars a year at one run a day), and the difference is mostly in wording. See [DeepSeek pricing](https://api-docs.deepseek.com/quick_start/pricing).

<br>

---

### 🛠️ Configuration

Edit the `CONFIG` dictionary in `nginx_digest.py`:
- `log_path`: Path to nginx access logs (rotated `.1` and `.gz` siblings are read too)
- `geoip_db_path` / `asn_db_path`: MaxMind databases
- `email_to`: Email settings (from `.env`)
- `llm_model`: LLM model to use for analysis (see [Changing the model](#changing-the-model))
- `session_timeout_minutes`: Session timeout for visitor sessions. This affects session counts by grouping requests from the same IP within this time window.
- `site_hosts`: from `SITE_HOSTS` in `.env`
- `beacon_path`, `verify_crawler_dns`, `min_modern_browser_version`, `datacenter_is_decisive`: classifier knobs (see "How traffic is classified")
- `history_path`, `history_days`: rolling baseline

Install dependencies on the server with `pip install -r requirements.txt` (this now includes `user-agents`, which was previously missing, so browser/OS parsing silently fell back to basic string matching).

<br>

---

### 🕓 Scheduling with Cron

Run daily at 14:00. That is off-peak for DeepSeek (half price) all year, whether the server clock is UTC or UK time: peak hours are 01:00-04:00 and 06:00-10:00 UTC, Monday to Friday. See [DeepSeek pricing](https://api-docs.deepseek.com/quick_start/pricing).

Option 1: Send output to cron.log

```cron
0 14 * * * /var/www/digest/run_digest.sh >> /var/www/digest/cron.log 2>&1
```

`cron.log` should be empty as the job is silent unless there are errors.

Option 2: Redirect to /dev/null (Recommended)

```cron
0 14 * * * /var/www/digest/run_digest.sh > /dev/null 2>&1
```

This discards any stdout/stderr from the script itself. Since all meaningful logs go to nginx_digest.log, you won't lose anything.

Option 3: Remove redirect entirely

Add this at the top of your crontab:

```cron
MAILTO="followcrom@gmail.com"
```

The MAILTO variable applies to all cron jobs below it. If anything unexpected outputs to stdout/stderr, cron will email it to you. Then the cron job line will be:

```cron
0 14 * * * /var/www/digest/run_digest.sh
```

With this version, you'll only get an email if something goes wrong and the script outputs an error that wasn't caught and logged to nginx_digest.log.   

The MAILTO is redundant since your bash script already handles errors, but it's a good safety net in case something goes wrong with the script itself (like syntax error, missing file, etc.).

<br>

---

### 🪓 Logging

The script creates two log outputs:

1. **Application Log**: `nginx_digest.log`
   - All script activity
   - Errors and warnings
   - Rotates automatically (if you set up logrotate)

2. **Cron Log**: `cron.log` (if you redirect in crontab)
   - Combined stdout/stderr from cron execution

Check log file size: `ls -lh nginx_digest.log`

#### 📒 Log Rotation Setup

Create `/etc/logrotate.d/nginx-digest`:
```
/home/followcrom/projects/nginx_digest/nginx_digest.log {
    daily
    missingok
    rotate 14
    compress
    notifempty
    create 0644 followcrom followcrom
}
```

Check the last 20 lines of the application log:
```bash
tail -20 /var/www/digest/nginx_digest.log
```

<br>

---

### 💾 Database Maintenance

- GeoLite2 databases are refreshed by MaxMind twice a week
- To update manually: `sudo geoipupdate`
- Database size: ~60 MB (City) + ~8 MB (ASN)
- `geoipupdate.timer` runs weekly once enabled (see the MaxMind GeoIP section)

<br>

---

### 🗄️ Files

- `nginx_digest.py`: Main script
- `run_digest.sh`: Wrapper script for cron
- `tests/`: Classifier tests and fixture logs
- `digest_history.jsonl`: Rolling daily summaries used for the baseline (gitignored)
- `.env`: Environment variables (`EMAIL_TO`, `GMAIL_ACCOUNT`, `GMAIL_PASSWORD`, `SITE_HOSTS`)
- `GeoIP.conf`: MaxMind configuration (mirrored in `/etc/GeoIP.conf`)
- `/var/lib/GeoIP/GeoLite2-City.mmdb`: Geolocation database
- `/var/lib/GeoIP/GeoLite2-ASN.mmdb`: Network/ASN database (optional but strongly recommended)

### Directory Structure 🧱

```
/var/www/digest/
├── dig_venv/              # Virtual environment
├── .llm/                  # LLM configuration
├── .env                   # Environment variables
├── nginx_digest.py        # Main Python script
├── requirements.txt       # Python dependencies
├── run_digest.sh          # Cron wrapper script
├── nginx_digest.log       # Application log
└── cron.log              # Cron output log
```

<br>

---

### 🔍 Monitoring

Check these regularly:

```bash
# View recent logs
tail -50 /var/www/digest/nginx_digest.log

# Check disk usage
du -sh /var/www/digest/*

# Verify cron is running
grep digest /var/log/syslog

# Check for errors
grep ERROR /var/www/digest/nginx_digest.log
```

<br>

---

## 🔅 uv

Check what Python versions you have:

```bash
uv python list
```

Create your venv with a specific version:

```bash
uv venv --python 3.13
```

I have version 3.13.9 installed, so I create a 3.13 venv with the above command. You don't need to specify the full path - uv finds it automatically from the list.

If you want a specific patch version:
```bash
uv venv --python 3.12.4
```

To activate the venv:
```bash
source .venv/bin/activate
```

You need to initialise the project first:
```bash
uv init
```

This creates a pyproject.toml. Then you can:
```bash
uv add llm
```

<br>

---

## 📅 Commit Activity 🕹️

![GitHub last commit](https://img.shields.io/github/last-commit/followcrom/nginx-digest)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/followcrom/nginx-digest)
![GitHub repo size](https://img.shields.io/github/repo-size/followcrom/nginx-digest)

## ✍ Authors 

🌍 followCrom: [followcrom.com](https://followcrom.com/index.html) 🌐

📫 followCrom: [get in touch](https://followcrom.com/contact/contact.php) 👋

[![Static Badge](https://img.shields.io/badge/followcrom-online-orange)](http://followcrom.com)