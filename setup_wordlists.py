"""Enterprise Wordlist Setup — Downloads and prepares all required wordlists."""

import argparse
import gzip
import os
import shutil
import urllib.request


def setup_enterprise_wordlists(force: bool = False):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    wordlists_dir = os.path.join(base_dir, "wordlists")
    os.makedirs(wordlists_dir, exist_ok=True)

    print("[*] Initializing Enterprise Wordlist Setup...")

    # 1. Extract Local RockYou
    rockyou_gz = os.path.join(base_dir, "rockyou.txt.gz")
    rockyou_txt = os.path.join(wordlists_dir, "rockyou.txt")

    if os.path.exists(rockyou_txt) and os.path.getsize(rockyou_txt) > 0 and not force:
        print(f"[+] EXISTS: {rockyou_txt} already present ({os.path.getsize(rockyou_txt):,} bytes). Skipping extraction.")
    elif os.path.exists(rockyou_gz):
        print(f"[*] Found {rockyou_gz}. Extracting...")
        try:
            with gzip.open(rockyou_gz, 'rb') as f_in:
                with open(rockyou_txt, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            print("[+] SUCCESS: rockyou.txt extracted and moved to wordlists/.")
        except Exception as e:
            print(f"[-] ERROR extracting RockYou: {e}")
    else:
        print(f"[-] WARNING: {rockyou_gz} not found in root directory. Skipping.")

    # 2. Download Probable-Wordlists (Top 12 Thousand)
    _download(
        "https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top12Thousand-probable-v2.txt",
        os.path.join(wordlists_dir, "probable.txt"),
        "Probable-Wordlists (Top 12k)",
        force=force,
    )

    # 3. Download Fasttrack (Password list)
    _download(
        "https://raw.githubusercontent.com/drtychai/wordlists/master/fasttrack.txt",
        os.path.join(wordlists_dir, "fasttrack.txt"),
        "Fasttrack password list",
        force=force,
    )

    # 4. Download DIRB Common (Directory brute-force)
    _download(
        "https://raw.githubusercontent.com/drtychai/wordlists/master/dirb/common.txt",
        os.path.join(wordlists_dir, "dirb_common.txt"),
        "DIRB Common (directory brute-force)",
        force=force,
    )

    # 5. Download DNSMap (Subdomain enumeration)
    _download(
        "https://raw.githubusercontent.com/drtychai/wordlists/master/dnsmap.txt",
        os.path.join(wordlists_dir, "dnsmap.txt"),
        "DNSMap (subdomain enumeration)",
        force=force,
    )

    # 6. Setup Technology-Specific Wordlists
    _setup_tech_wordlists(wordlists_dir)

    print("\n[!] ALL TASKS COMPLETED. Wordlists are ready in /wordlists.")


def _setup_tech_wordlists(wordlists_dir: str) -> None:
    """Create curated technology-specific wordlists for adaptive fuzzing."""
    tech_dir = os.path.join(wordlists_dir, "tech")
    os.makedirs(tech_dir, exist_ok=True)

    tech_lists = {
        "wordpress.txt": [
            "wp-login.php", "wp-admin", "wp-content", "wp-includes", "xmlrpc.php",
            "wp-json/wp/v2/users", "wp-config.php.bak", "wp-config.php.dist", "wp-config.old",
            "wp-content/debug.log", "wp-content/plugins", "wp-content/themes",
            "readme.html", "license.txt", "wp-links-opml.php", "wp-cron.php",
        ],
        "php.txt": [
            "info.php", "phpinfo.php", "test.php", "config.php", "db.php",
            "database.php", "connect.php", "admin.php", "login.php", "upload.php",
            "shell.php", "eval.php", "cmd.php", "composer.json", "composer.lock",
            "phpmyadmin", "pma", "server-status", "web.config", ".htaccess",
        ],
        "spring.txt": [
            "actuator", "actuator/health", "actuator/env", "actuator/beans",
            "actuator/configprops", "actuator/heapdump", "actuator/mappings",
            "actuator/metrics", "actuator/info", "actuator/threaddump",
            "swagger-ui.html", "v2/api-docs", "v3/api-docs", "swagger-ui/",
            "api-docs", "hystrix", "turbine", "eureka", "druid/index.html",
        ],
        "api.txt": [
            "api", "api/v1", "api/v2", "api/v3", "v1", "v2", "graphql",
            "graphiql", "swagger", "swagger-ui", "openapi.json", "openapi.yaml",
            "docs", "documentation", "health", "healthz", "metrics", "status",
            "auth/login", "auth/token", "oauth/token", "user/profile",
        ],
        "sensitive_files.txt": [
            ".env", ".env.local", ".env.production", ".env.bak",
            ".git/config", ".git/HEAD", ".gitignore", ".svn/entries",
            "backup.sql", "dump.sql", "database.sql", "users.sql",
            "config.json", "config.yaml", "settings.py", "docker-compose.yml",
            "Dockerfile", "id_rsa", "id_rsa.pub", "credentials.json",
        ],
    }

    for filename, entries in tech_lists.items():
        filepath = os.path.join(tech_dir, filename)
        if not os.path.exists(filepath) or os.path.getsize(filepath) < 10:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(entries) + "\n")
            print(f"[+] CREATED: wordlists/tech/{filename} ({len(entries)} entries)")


def _download(url: str, dest: str, label: str, force: bool = False) -> None:
    """Download a single file with caching, validation, timeout, and atomic file writing."""
    if os.path.exists(dest) and os.path.getsize(dest) > 100 and not force:
        print(f"[+] EXISTS: {os.path.basename(dest)} already present ({os.path.getsize(dest):,} bytes). Skipping download.")
        return

    print(f"[*] Downloading {label}...")
    tmp_dest = dest + ".tmp"
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
            },
        )
        with urllib.request.urlopen(req, timeout=25) as resp:
            if resp.status != 200:
                print(f"[-] HTTP Error {resp.status} downloading {label}.")
                return
            content = resp.read()

        # Sanity check: Ensure we didn't receive a short error page (e.g. 404 text)
        if len(content) < 50 and b"404" in content:
            print(f"[-] ERROR: Received 404 page for {label}. Skipping.")
            return

        with open(tmp_dest, "wb") as f_out:
            f_out.write(content)

        # Atomic replacement
        if os.path.exists(dest):
            os.remove(dest)
        os.rename(tmp_dest, dest)
        print(f"[+] SUCCESS: {os.path.basename(dest)} downloaded ({len(content):,} bytes).")
    except Exception as e:
        if os.path.exists(tmp_dest):
            try:
                os.remove(tmp_dest)
            except OSError:
                pass
        print(f"[-] ERROR downloading {label}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enterprise Wordlist Setup")
    parser.add_argument("--force", action="store_true", help="Force re-extraction and re-download of wordlists even if already present")
    args = parser.parse_args()
    setup_enterprise_wordlists(force=args.force)

