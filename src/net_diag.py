"""Network connectivity and DNS latency diagnostic module for VPS-Guardian-MCP.

Provides 100% pure Python, shell-less network diagnostics:
- Outbound socket latency benchmarking (DNS, TCP, and TLS handshake times).
- System DNS resolver health and upstream nameserver responsiveness audits.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("vps_guardian.net_diag")

HOST_REGEX = re.compile(r"^[a-zA-Z0-9.-]{1,253}$")
DEFAULT_TEST_DOMAINS = ["google.com", "cloudflare.com", "github.com", "api.openai.com"]


def test_network_connectivity(
    target_host: str,
    port: int = 443,
    timeout_seconds: float = 5.0,
) -> Dict[str, Any]:
    """Benchmark outbound network connectivity and latency to a remote endpoint.

    Uses safe, direct Python socket operations (zero shell execution) to isolate:
    - DNS resolution latency.
    - TCP connection handshake latency.
    - TLS cryptographic handshake latency (for port 443 or SSL targets).

    Args:
        target_host: Destination hostname or IP address (e.g. 'api.github.com' or '8.8.8.8').
        port: Destination port (1-65535, default 443).
        timeout_seconds: Network socket timeout (0.5 to 30.0 seconds, default 5.0).

    Returns:
        Structured dictionary with stage latency breakdown, resolved IP addresses,
        and TLS session details.
    """
    if not isinstance(target_host, str) or not target_host.strip():
        return {"status": "error", "error": "target_host must be a non-empty string."}

    clean_host = target_host.strip().lower()
    # Strip URL schemes if user passed http:// or https://
    if "://" in clean_host:
        clean_host = clean_host.split("://", 1)[1]
    if "/" in clean_host:
        clean_host = clean_host.split("/", 1)[0]
    if ":" in clean_host and not clean_host.startswith("["):
        parts = clean_host.split(":")
        clean_host = parts[0]
        try:
            port = int(parts[1])
        except (ValueError, TypeError):
            pass

    if not HOST_REGEX.match(clean_host):
        return {
            "status": "error",
            "error": f"Invalid target_host '{clean_host}'. Only valid hostnames or IP addresses allowed.",
        }

    try:
        port = max(1, min(int(port), 65535))
        timeout = max(0.5, min(float(timeout_seconds), 30.0))
    except (ValueError, TypeError):
        port = 443
        timeout = 5.0

    # Step 1: DNS Resolution Benchmark
    dns_start = time.perf_counter()
    resolved_ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(clean_host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = list({info[4][0] for info in addr_info if info[4]})
    except socket.gaierror as exc:
        dns_duration = (time.perf_counter() - dns_start) * 1000.0
        return {
            "status": "unreachable",
            "target": f"{clean_host}:{port}",
            "failed_stage": "dns",
            "error": f"DNS resolution failed for '{clean_host}': {str(exc)}",
            "dns_latency_ms": round(dns_duration, 2),
        }
    except Exception as exc:
        return {
            "status": "error",
            "target": f"{clean_host}:{port}",
            "failed_stage": "dns",
            "error": f"Resolution error: {str(exc)}",
        }

    dns_latency_ms = (time.perf_counter() - dns_start) * 1000.0
    primary_ip = resolved_ips[0] if resolved_ips else clean_host

    # Step 2: TCP Handshake Benchmark
    tcp_start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((primary_ip, port), timeout=timeout)
    except socket.timeout:
        tcp_duration = (time.perf_counter() - tcp_start) * 1000.0
        return {
            "status": "unreachable",
            "target": f"{clean_host}:{port}",
            "target_ip": primary_ip,
            "failed_stage": "tcp",
            "error": f"Connection timed out after {timeout} seconds connecting to {primary_ip}:{port}.",
            "dns_latency_ms": round(dns_latency_ms, 2),
            "tcp_latency_ms": round(tcp_duration, 2),
        }
    except ConnectionRefusedError:
        tcp_duration = (time.perf_counter() - tcp_start) * 1000.0
        return {
            "status": "unreachable",
            "target": f"{clean_host}:{port}",
            "target_ip": primary_ip,
            "failed_stage": "tcp",
            "error": f"Connection refused by {primary_ip}:{port}.",
            "dns_latency_ms": round(dns_latency_ms, 2),
            "tcp_latency_ms": round(tcp_duration, 2),
        }
    except Exception as exc:
        tcp_duration = (time.perf_counter() - tcp_start) * 1000.0
        return {
            "status": "error",
            "target": f"{clean_host}:{port}",
            "target_ip": primary_ip,
            "failed_stage": "tcp",
            "error": f"TCP connection error: {str(exc)}",
            "dns_latency_ms": round(dns_latency_ms, 2),
            "tcp_latency_ms": round(tcp_duration, 2),
        }

    tcp_latency_ms = (time.perf_counter() - tcp_start) * 1000.0

    # Step 3: TLS Handshake Benchmark (if port is 443 or ssl target)
    tls_latency_ms: Optional[float] = None
    tls_info: Optional[Dict[str, Any]] = None

    if port == 443:
        tls_start = time.perf_counter()
        try:
            context = ssl.create_default_context()
            tls_sock = context.wrap_socket(sock, server_hostname=clean_host)
            tls_latency_ms = (time.perf_counter() - tls_start) * 1000.0
            cipher_info = tls_sock.cipher()
            tls_info = {
                "version": tls_sock.version(),
                "cipher_suite": cipher_info[0] if cipher_info else None,
            }
            tls_sock.close()
        except Exception as exc:
            tls_duration = (time.perf_counter() - tls_start) * 1000.0
            if sock:
                sock.close()
            return {
                "status": "error",
                "target": f"{clean_host}:{port}",
                "target_ip": primary_ip,
                "failed_stage": "tls",
                "error": f"TLS handshake failed: {str(exc)}",
                "dns_latency_ms": round(dns_latency_ms, 2),
                "tcp_latency_ms": round(tcp_latency_ms, 2),
                "tls_latency_ms": round(tls_duration, 2),
            }
    else:
        if sock:
            sock.close()

    total_latency_ms = dns_latency_ms + tcp_latency_ms + (tls_latency_ms or 0.0)

    return {
        "status": "ok",
        "reachable": True,
        "target": f"{clean_host}:{port}",
        "primary_ip": primary_ip,
        "resolved_ips": resolved_ips,
        "dns_latency_ms": round(dns_latency_ms, 2),
        "tcp_latency_ms": round(tcp_latency_ms, 2),
        "tls_latency_ms": round(tls_latency_ms, 2) if tls_latency_ms is not None else None,
        "total_latency_ms": round(total_latency_ms, 2),
        "tls": tls_info,
        "summary": (
            f"Successfully connected to '{clean_host}:{port}' ({primary_ip}). "
            f"Latency: DNS {dns_latency_ms:.1f}ms, TCP {tcp_latency_ms:.1f}ms"
            + (f", TLS {tls_latency_ms:.1f}ms" if tls_latency_ms else "")
            + f" (Total: {total_latency_ms:.1f}ms)."
        ),
    }


def check_dns_health(domains: Optional[List[str]] = None) -> Dict[str, Any]:
    """Audit system DNS resolution health, configured nameservers, and query responsiveness.

    Checks:
    - /etc/resolv.conf nameservers.
    - Benchmarks resolution latency against essential public services (Google, Cloudflare, GitHub, OpenAI).

    Args:
        domains: Optional custom list of domains to probe. Defaults to standard services.

    Returns:
        Structured dictionary with nameservers, individual test latencies, and overall health status.
    """
    test_domains = domains if isinstance(domains, list) and domains else DEFAULT_TEST_DOMAINS

    # Read nameservers from /etc/resolv.conf
    nameservers: List[str] = []
    search_domains: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        nameservers.append(parts[1])
                elif line.startswith("search") or line.startswith("domain"):
                    parts = line.split()
                    search_domains.extend(parts[1:])
    except Exception as exc:
        logger.debug(f"Could not read /etc/resolv.conf: {exc}")

    probe_results: List[Dict[str, Any]] = []
    total_time_ms = 0.0
    failures_count = 0

    for dom in test_domains:
        d_clean = dom.strip().lower()
        if not HOST_REGEX.match(d_clean):
            continue

        start_t = time.perf_counter()
        try:
            addrs = socket.getaddrinfo(d_clean, 80, socket.AF_INET, socket.SOCK_STREAM)
            lat = (time.perf_counter() - start_t) * 1000.0
            ips = list({a[4][0] for a in addrs if a[4]})
            probe_results.append(
                {
                    "domain": d_clean,
                    "resolved": True,
                    "latency_ms": round(lat, 2),
                    "ips": ips[:4],
                }
            )
            total_time_ms += lat
        except Exception as exc:
            lat = (time.perf_counter() - start_t) * 1000.0
            failures_count += 1
            probe_results.append(
                {
                    "domain": d_clean,
                    "resolved": False,
                    "latency_ms": round(lat, 2),
                    "error": str(exc),
                }
            )

    successful_probes = len(probe_results) - failures_count
    avg_latency = round(total_time_ms / successful_probes, 2) if successful_probes > 0 else None

    healthy = (failures_count == 0) and (avg_latency is not None and avg_latency < 300.0)

    return {
        "status": "ok",
        "healthy": healthy,
        "configured_nameservers": nameservers,
        "search_domains": search_domains,
        "total_tested": len(probe_results),
        "failed_lookups": failures_count,
        "average_latency_ms": avg_latency,
        "probe_results": probe_results,
        "summary": (
            f"DNS Health: {'HEALTHY' if healthy else 'DEGRADED'}. "
            f"Tested {len(probe_results)} domains, {failures_count} failures, "
            f"avg latency {avg_latency or 0.0}ms."
        ),
    }
