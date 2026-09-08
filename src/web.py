"""Web server and SSL certificate inspection module for VPS-Guardian-MCP.

Provides safe diagnostic tools for:
- Testing Nginx configuration syntax (nginx -t) prior to reloads.
- Auditing SSL/TLS certificates (expiration dates, domains, renewal warnings).
- Parsing active Nginx virtual hosts (domains, listening ports, reverse proxy targets).
"""

from __future__ import annotations

import datetime
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.web")


def test_nginx_config() -> Dict[str, Any]:
    """Test the Nginx web server configuration for syntax errors ('nginx -t').

    Safe read-only check to run prior to reloading or restarting Nginx.

    Returns:
        Structured dictionary indicating syntax validity, test outcome, and detailed error logs.
    """
    nginx_bin = shutil.which("nginx") or "/usr/sbin/nginx"
    if not shutil.which(nginx_bin):
        return {
            "status": "unavailable",
            "error": "Nginx binary not found on this system.",
            "syntax_valid": False,
            "test_successful": False,
        }

    try:
        proc = subprocess.run(
            [nginx_bin, "-t"],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )

        output = proc.stdout.strip()
        error_output = proc.stderr.strip()
        combined = f"{output}\n{error_output}".strip()

        # Nginx writes configuration test results to stderr by convention
        syntax_ok = "syntax is ok" in combined.lower()
        test_ok = "test is successful" in combined.lower()

        error_details = ""
        if not (syntax_ok and test_ok):
            error_details = combined

        return {
            "status": "ok",
            "syntax_valid": syntax_ok,
            "test_successful": test_ok,
            "exit_code": proc.returncode,
            "error_details": error_details,
            "raw_output": combined,
        }
    except subprocess.TimeoutExpired:
        return {
            "status": "error",
            "error": "Timeout while running 'nginx -t'.",
            "syntax_valid": False,
            "test_successful": False,
        }
    except PermissionError as exc:
        return {
            "status": "error",
            "error": f"Permission denied executing 'nginx -t': {str(exc)}",
            "syntax_valid": False,
            "test_successful": False,
        }
    except Exception as exc:
        logger.error(f"Unexpected error testing Nginx config: {exc}", exc_info=True)
        return {
            "status": "error",
            "error": f"Failed running 'nginx -t': {str(exc)}",
            "syntax_valid": False,
            "test_successful": False,
        }


def check_ssl_certificates() -> Dict[str, Any]:
    """Audit SSL/TLS certificates configured on the host (Certbot / Let's Encrypt / custom).

    Parses certificates in /etc/letsencrypt/live/ and verifies expiration timestamps.
    Warns if any certificate expires within 14 days.

    Returns:
        Structured dictionary listing discovered certificates, valid domains,
        expiry dates, and expiration warnings.
    """
    certificates: List[Dict[str, Any]] = []
    expiring_soon_count = 0
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Primary check: certbot certificates CLI if available
    certbot_bin = shutil.which("certbot")
    if certbot_bin:
        try:
            res = subprocess.run(
                [certbot_bin, "certificates"],
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            if res.returncode == 0 and res.stdout.strip():
                cert_blocks = re.findall(
                    r"Certificate Name:\s*([^\n]+).*?Domains:\s*([^\n]+).*?Expiry Date:\s*([^\n]+).*?Certificate Path:\s*([^\n]+)",
                    res.stdout,
                    re.DOTALL,
                )
                for name, domains, expiry_str, cert_path in cert_blocks:
                    # Clean fields
                    c_name = name.strip()
                    c_domains = [d.strip() for d in domains.split()]
                    c_expiry_clean = expiry_str.strip()
                    c_path = cert_path.strip()

                    # Extract days remaining if present e.g. "(VALID: 82 days)"
                    days_match = re.search(r"VALID:\s*(\d+)\s*day", c_expiry_clean)
                    days_remaining = int(days_match.group(1)) if days_match else None
                    is_expiring = days_remaining is not None and days_remaining <= 14

                    if is_expiring:
                        expiring_soon_count += 1

                    certificates.append({
                        "name": c_name,
                        "domains": c_domains,
                        "expiry_raw": c_expiry_clean,
                        "days_remaining": days_remaining,
                        "is_expiring_soon": is_expiring,
                        "certificate_path": c_path,
                    })
        except Exception as exc:
            logger.debug(f"certbot CLI parsing failed: {exc}")

    # 2. Secondary check: Direct inspect /etc/letsencrypt/live/ if CLI returned nothing
    letsencrypt_live = "/etc/letsencrypt/live"
    if not certificates and os.path.exists(letsencrypt_live) and os.path.isdir(letsencrypt_live):
        try:
            for domain_dir in sorted(os.listdir(letsencrypt_live)):
                full_dir = os.path.join(letsencrypt_live, domain_dir)
                cert_file = os.path.join(full_dir, "cert.pem")
                if os.path.isdir(full_dir) and os.path.exists(cert_file):
                    # Use openssl x509 to read expiration
                    expiry_date = None
                    days_left = None
                    if shutil.which("openssl"):
                        try:
                            ssl_proc = subprocess.run(
                                ["openssl", "x509", "-enddate", "-noout", "-in", cert_file],
                                capture_output=True,
                                text=True,
                                check=False,
                                timeout=5,
                            )
                            if ssl_proc.returncode == 0:
                                # notAfter=May 25 12:00:00 2026 GMT
                                date_str = ssl_proc.stdout.replace("notAfter=", "").strip()
                                parsed_date = datetime.datetime.strptime(
                                    date_str, "%b %d %H:%M:%S %Y %Z"
                                ).replace(tzinfo=datetime.timezone.utc)
                                expiry_date = parsed_date.isoformat()
                                delta = parsed_date - now
                                days_left = max(0, delta.days)
                        except Exception:
                            pass

                    is_expiring = days_left is not None and days_left <= 14
                    if is_expiring:
                        expiring_soon_count += 1

                    certificates.append({
                        "name": domain_dir,
                        "domains": [domain_dir],
                        "expiry_date": expiry_date,
                        "days_remaining": days_left,
                        "is_expiring_soon": is_expiring,
                        "certificate_path": cert_file,
                    })
        except Exception as exc:
            logger.debug(f"Direct /etc/letsencrypt/live inspection error: {exc}")

    return {
        "status": "ok",
        "total_certificates": len(certificates),
        "expiring_soon_count": expiring_soon_count,
        "certificates": certificates,
    }


def list_virtual_hosts() -> Dict[str, Any]:
    """Parse active Nginx virtual hosts from /etc/nginx/sites-enabled/ and conf.d/.

    Extracts server names, listening ports, SSL configurations, and proxy_pass targets.

    Returns:
        Structured dictionary listing all configured virtual hosts.
    """
    sites_dirs = ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"]
    vhosts: List[Dict[str, Any]] = []

    for s_dir in sites_dirs:
        if not os.path.exists(s_dir) or not os.path.isdir(s_dir):
            continue

        for filename in sorted(os.listdir(s_dir)):
            if filename.startswith(".") or not (filename.endswith(".conf") or s_dir.endswith("sites-enabled")):
                continue

            file_path = os.path.join(s_dir, filename)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()

                # Extract server blocks
                server_blocks = re.findall(r"server\s*\{(.*?)\n\s*\}", content, re.DOTALL)
                if not server_blocks:
                    server_blocks = [content]

                for block in server_blocks:
                    # Parse listen ports
                    listens = re.findall(r"listen\s+([^;]+);", block)
                    clean_listens = [l.strip() for l in listens]

                    # Parse server_name
                    server_names = re.findall(r"server_name\s+([^;]+);", block)
                    domains: List[str] = []
                    for sn in server_names:
                        domains.extend(sn.strip().split())

                    # Parse proxy_pass directives
                    proxies = re.findall(r"proxy_pass\s+([^;]+);", block)
                    clean_proxies = [p.strip() for p in proxies]

                    # Check for SSL
                    has_ssl = any("ssl" in l.lower() for l in clean_listens) or "ssl_certificate" in block

                    if clean_listens or domains or clean_proxies:
                        vhosts.append({
                            "config_file": file_path,
                            "domains": domains if domains else ["_"],
                            "listen_ports": clean_listens,
                            "has_ssl": has_ssl,
                            "proxy_pass_targets": clean_proxies,
                        })
            except Exception as exc:
                logger.debug(f"Error parsing vhost in {file_path}: {exc}")
                continue

    return {
        "status": "ok",
        "total_virtual_hosts": len(vhosts),
        "virtual_hosts": vhosts,
    }
