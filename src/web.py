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
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.web")

MAX_HTTP_TIMEOUT_SECONDS = 30
MAX_RESPONSE_BYTES = 256 * 1024


def check_http_endpoint(
    url: str,
    expected_status: int = 200,
    expected_text: Optional[str] = None,
    timeout_seconds: int = 10,
) -> Dict[str, Any]:
    """Check a public HTTP(S) endpoint and return a compact deployment-ready result.

    Follows normal redirects, verifies TLS certificates, caps the response read size,
    and never exposes response bodies.  ``expected_text`` is only used as a
    presence check, making it useful for detecting a wrong virtual host or stale page.
    """
    if not isinstance(url, str) or len(url) > 2048:
        return {"status": "error", "error": "url must be a non-empty URL up to 2048 characters."}
    parsed = urllib.parse.urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return {"status": "error", "error": "Only absolute http:// or https:// URLs are supported."}
    if not isinstance(expected_status, int) or not 100 <= expected_status <= 599:
        return {"status": "error", "error": "expected_status must be an HTTP status from 100 to 599."}
    if expected_text is not None and (not isinstance(expected_text, str) or len(expected_text) > 512):
        return {"status": "error", "error": "expected_text must be a string up to 512 characters."}
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= MAX_HTTP_TIMEOUT_SECONDS:
        return {"status": "error", "error": f"timeout_seconds must be between 1 and {MAX_HTTP_TIMEOUT_SECONDS}."}

    request = urllib.request.Request(
        parsed.geturl(),
        headers={"User-Agent": "VPS-Guardian-MCP/0.15 endpoint-check"},
        method="GET",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
            elapsed_ms = round((time.monotonic() - started) * 1000, 1)
            truncated = len(body) > MAX_RESPONSE_BYTES
            body = body[:MAX_RESPONSE_BYTES]
            charset = response.headers.get_content_charset() or "utf-8"
            text = body.decode(charset, errors="replace") if expected_text is not None else ""
            actual_status = response.getcode()
            text_found = expected_text in text if expected_text is not None else None
            checks_passed = actual_status == expected_status and (text_found is not False)
            return {
                "status": "ok" if checks_passed else "warning",
                "url": parsed.geturl(),
                "final_url": response.geturl(),
                "http_status": actual_status,
                "expected_status": expected_status,
                "latency_ms": elapsed_ms,
                "content_type": response.headers.get("Content-Type"),
                "redirected": response.geturl() != parsed.geturl(),
                "expected_text_checked": expected_text is not None,
                "expected_text_found": text_found,
                "response_truncated": truncated,
                "healthy": checks_passed,
            }
    except urllib.error.HTTPError as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        return {
            "status": "warning",
            "url": parsed.geturl(),
            "final_url": exc.geturl(),
            "http_status": exc.code,
            "expected_status": expected_status,
            "latency_ms": elapsed_ms,
            "healthy": False,
            "error": f"Endpoint returned HTTP {exc.code}.",
        }
    except Exception as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        return {
            "status": "error",
            "url": parsed.geturl(),
            "latency_ms": elapsed_ms,
            "healthy": False,
            "error": f"Endpoint request failed: {str(exc)}",
        }


def get_web_deployment_status(
    domain: str,
    path: str = "/",
    expected_status: int = 200,
    expected_text: Optional[str] = None,
) -> Dict[str, Any]:
    """Correlate a public HTTPS response with local Nginx and certificate state."""
    clean_domain = domain.strip().lower() if isinstance(domain, str) else ""
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", clean_domain):
        return {"status": "error", "error": "domain must be a valid hostname."}
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 1024:
        return {"status": "error", "error": "path must start with '/' and be at most 1024 characters."}

    endpoint = check_http_endpoint(
        f"https://{clean_domain}{path}", expected_status, expected_text
    )
    vhosts = list_virtual_hosts()
    matching_vhosts = [
        host for host in vhosts.get("virtual_hosts", [])
        if clean_domain in [item.lower() for item in host.get("domains", [])]
    ]
    certificates = check_ssl_certificates()
    matching_certificates = [
        certificate for certificate in certificates.get("certificates", [])
        if clean_domain in [item.lower() for item in certificate.get("domains", [])]
    ]
    config_ok = bool(matching_vhosts)
    cert_ok = bool(matching_certificates) and not any(
        item.get("is_expiring_soon") for item in matching_certificates
    )
    healthy = endpoint.get("healthy") is True and config_ok and cert_ok
    issues: List[str] = []
    if not endpoint.get("healthy"):
        issues.append("The public endpoint did not meet the expected response check.")
    if not config_ok:
        issues.append("No matching Nginx virtual host was found locally.")
    if not matching_certificates:
        issues.append("No local certificate matching this domain was found.")
    elif not cert_ok:
        issues.append("A matching certificate expires soon.")
    return {
        "status": "ok" if healthy else "warning",
        "domain": clean_domain,
        "path": path,
        "healthy": healthy,
        "endpoint": endpoint,
        "matching_virtual_hosts": matching_vhosts,
        "matching_certificates": matching_certificates,
        "issues": issues,
    }


def check_http_endpoints(endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Check up to 20 endpoint definitions and summarize deployment health."""
    if not isinstance(endpoints, list) or not endpoints:
        return {"status": "error", "error": "endpoints must be a non-empty list."}
    if len(endpoints) > 20:
        return {"status": "error", "error": "At most 20 endpoints can be checked at once."}
    results: List[Dict[str, Any]] = []
    for index, endpoint in enumerate(endpoints, start=1):
        if not isinstance(endpoint, dict):
            results.append({"index": index, "status": "error", "healthy": False, "error": "Endpoint must be an object."})
            continue
        result = check_http_endpoint(
            endpoint.get("url"),
            endpoint.get("expected_status", 200),
            endpoint.get("expected_text"),
            endpoint.get("timeout_seconds", 10),
        )
        result["index"] = index
        results.append(result)
    healthy_count = sum(1 for result in results if result.get("healthy") is True)
    return {
        "status": "ok" if healthy_count == len(results) else "warning",
        "total_endpoints": len(results),
        "healthy_endpoints": healthy_count,
        "unhealthy_endpoints": len(results) - healthy_count,
        "healthy": healthy_count == len(results),
        "results": results,
    }


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
