# 📊 Nginx Analytics Daily Digest 🍽️ 😋

Parses nginx access logs, generates visitor analytics with geolocation data, gets LLM commentary, and sends a daily email digest.

```bash
source .venv/bin/activate
```

### 📍 MaxMind GeoIP

`geoip2` is just the Python library with no config. You also need the GeoIP database file from MaxMind. `geoipupdate` is the official tool to download and update the databases. `geoipupdate` is installed system-wide.

1. **geoipupdate is installed globally on SURFACE:**
   ```bash
   sudo apt-get install geoipupdate
   ```

2. **Configure credentials:**
   - Ensure `GeoIP.conf` is in `/etc/GeoIP.conf`. This file includes details like:

     ```
     AccountID
     LicenseKey
     Databases - in this case, GeoLite2-City
     DatabaseDirectory /var/lib/GeoIP
     ```

3. **Download database:**
   ```bash
   sudo geoipupdate
   ```

   This downloads `GeoLite2-City.mmdb` (~60MB) to `/var/lib/GeoIP/`. **This database is already downloaded.** It is regularly updated by MaxMind.

4. **Automatic updates:**
   - A systemd timer (`geoipupdate.timer`) is installed but **currently disabled**
   - To enable automatic weekly updates: `sudo systemctl enable geoipupdate.timer`

5. **Manual updates**
   - To update manually anytime: `sudo geoipupdate`
   - Just download a fresh `.mmdb` from your MaxMind account whenever you want and copy it over.
   - For a personal portfolio site's analytics, honestly manual updates every few months (or never) is probably fine. The IP-to-location mappings don't change that dramatically. 

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

<br>

---

### 🛠️ Configuration

Edit the `CONFIG` dictionary in `nginx_digest.py`:
- `log_path`: Path to nginx access logs
- `email_to`: Email settings
- `llm_model`: LLM model to use for analysis
- `session_timeout_minutes`: Session timeout for visitor sessions. This affects session counts by grouping requests from the same IP within this time window.

<br>

---

### 🕓 Scheduling with Cron

Run daily at 6 AM.

Option 1: Send output to cron.log

```cron
0 6 * * * /var/www/digest/run_digest.sh >> /var/www/digest/cron.log 2>&1
```

`cron.log` should be empty as the job is silent unless there are errors.

Option 2: Redirect to /dev/null (Recommended)

```cron
0 6 * * * /var/www/digest/run_digest.sh > /dev/null 2>&1
```

This discards any stdout/stderr from the script itself. Since all meaningful logs go to nginx_digest.log, you won't lose anything.

Option 3: Remove redirect entirely

Add this at the top of your crontab:

```cron
MAILTO="followcrom@gmail.com"
```

The MAILTO variable applies to all cron jobs below it. If anything unexpected outputs to stdout/stderr, cron will email it to you. Then the cron job line will be:

```cron
0 6 * * * /var/www/digest/run_digest.sh
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

- GeoLite2 databases are updated by MaxMind monthly
- To update manually: `sudo geoipupdate`
- Database size: ~70-80 MB (GeoLite2-City only)
- Note: `geoipupdate.timer` exists but is disabled - enable if you want automatic updates

<br>

---

### 🗄️ Files

- `nginx_analytics_digest.py`: Main script
- `run_digest.sh`: Wrapper script for cron
- `.env`: Environment variables
- `GeoIP.conf`: MaxMind configuration (mirrored in `/etc/GeoIP.conf`)
- `/var/lib/GeoIP/GeoLite2-City.mmdb`: Geolocation database

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