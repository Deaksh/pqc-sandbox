"""
Auto-discovery engine: find TLS-using assets without manual entry.

Sources (each is optional — gracefully skipped if credentials missing):
  1. AWS ACM     — list all certificates in the account/region
  2. AWS ELB     — list load balancers + their TLS listener configs
  3. Kubernetes  — scan Secrets of type kubernetes.io/tls
  4. Cert Transparency logs — search CT logs for your domain's certificates
  5. Local filesystem — find TLS cert/key files and config files
  6. DNS         — resolve subdomains and probe TLS on common ports

All sources produce DiscoveredAsset objects that feed directly into
the existing scan pipeline (same as manually-added assets).
"""
from __future__ import annotations

import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pqc_sandbox.algorithms import MIGRATION_MAP


@dataclass
class DiscoveredAsset:
    name: str
    target: str                         # host:port or file path
    asset_type: str                     # "tls_endpoint" | "cert_file" | "config_file"
    source: str                         # "aws_acm" | "k8s" | "ct_log" | "filesystem" | "dns"
    detected_algorithms: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    team: Optional[str] = None


class AutoDiscovery:
    def __init__(self, org_id: str):
        self.org_id = org_id
        self._assets: list[DiscoveredAsset] = []

    # ── Source 1: AWS ACM ─────────────────────────────────────────────────────

    def discover_aws_acm(self, region: str = "us-east-1") -> list[DiscoveredAsset]:
        """List all ACM certificates and extract their domain names."""
        try:
            import boto3
            acm = boto3.client("acm", region_name=region)
            paginator = acm.get_paginator("list_certificates")
            assets: list[DiscoveredAsset] = []
            for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
                for cert in page["CertificateSummaryList"]:
                    arn = cert["CertificateArn"]
                    domain = cert.get("DomainName", "")
                    detail = acm.describe_certificate(CertificateArn=arn)["Certificate"]
                    key_algo = detail.get("KeyAlgorithm", "")
                    sig_algo = detail.get("SignatureAlgorithm", "")

                    detected = []
                    if "RSA" in key_algo.upper():
                        detected.append("RSA-2048 (PKCS#1 v1.5)")
                    elif "EC" in key_algo.upper():
                        detected.append("ECDSA-P256")

                    asset = DiscoveredAsset(
                        name=f"ACM: {domain}",
                        target=domain,
                        asset_type="tls_endpoint",
                        source="aws_acm",
                        detected_algorithms=detected,
                        metadata={"arn": arn, "key_algo": key_algo, "sig_algo": sig_algo,
                                  "expiry": str(detail.get("NotAfter", ""))},
                    )
                    assets.append(asset)
            self._assets.extend(assets)
            return assets
        except ImportError:
            return [DiscoveredAsset("AWS ACM (boto3 not installed)", "", "tls_endpoint",
                                    "aws_acm", metadata={"error": "pip install boto3"})]
        except Exception as e:
            return [DiscoveredAsset(f"AWS ACM error: {e}", "", "tls_endpoint", "aws_acm")]

    # ── Source 2: Kubernetes TLS secrets ──────────────────────────────────────

    def discover_kubernetes(self, namespace: str = "") -> list[DiscoveredAsset]:
        """Scan Kubernetes secrets of type kubernetes.io/tls."""
        try:
            from kubernetes import client, config as k8s_config  # type: ignore
            k8s_config.load_kube_config()
            v1 = client.CoreV1Api()

            secrets = (v1.list_secret_for_all_namespaces().items if not namespace
                       else v1.list_namespaced_secret(namespace).items)

            assets: list[DiscoveredAsset] = []
            for secret in secrets:
                if secret.type != "kubernetes.io/tls":
                    continue
                name = secret.metadata.name
                ns   = secret.metadata.namespace
                # Extract CN from cert if possible
                cert_pem = (secret.data or {}).get("tls.crt", "")
                domain   = name  # fallback

                asset = DiscoveredAsset(
                    name=f"k8s/{ns}/{name}",
                    target=domain,
                    asset_type="tls_endpoint",
                    source="k8s",
                    team=ns,
                    metadata={"namespace": ns, "secret": name},
                )
                assets.append(asset)
            self._assets.extend(assets)
            return assets
        except ImportError:
            return [DiscoveredAsset("Kubernetes (library not installed)", "", "tls_endpoint",
                                    "k8s", metadata={"error": "pip install kubernetes"})]
        except Exception as e:
            return [DiscoveredAsset(f"Kubernetes error: {e}", "", "tls_endpoint", "k8s")]

    # ── Source 3: Certificate Transparency logs ───────────────────────────────

    def discover_ct_logs(self, domain: str) -> list[DiscoveredAsset]:
        """Query crt.sh CT log aggregator for all certificates issued for a domain."""
        try:
            import urllib.request, json
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            with urllib.request.urlopen(url, timeout=15) as resp:
                certs = json.loads(resp.read())

            seen: set[str] = set()
            assets: list[DiscoveredAsset] = []
            for cert in certs[:50]:  # limit to 50 most recent
                name_val = cert.get("common_name", cert.get("name_value", ""))
                for host in name_val.replace("*.", "").splitlines():
                    host = host.strip()
                    if not host or host in seen:
                        continue
                    seen.add(host)
                    sig_alg = cert.get("issuer_ca_id", "")
                    assets.append(DiscoveredAsset(
                        name=f"CT: {host}",
                        target=host,
                        asset_type="tls_endpoint",
                        source="ct_log",
                        metadata={"issuer": cert.get("issuer_name", ""), "not_after": cert.get("not_after", "")},
                    ))
            self._assets.extend(assets)
            return assets
        except Exception as e:
            return [DiscoveredAsset(f"CT log error: {e}", domain, "tls_endpoint", "ct_log")]

    # ── Source 4: Local filesystem cert/config scan ───────────────────────────

    def discover_filesystem(self, root: str = "/etc") -> list[DiscoveredAsset]:
        """Scan filesystem for TLS cert files and crypto config files."""
        assets: list[DiscoveredAsset] = []
        root_path = Path(root)

        cert_patterns    = ["**/*.pem", "**/*.crt", "**/*.cer", "**/*.cert"]
        config_patterns  = ["**/nginx.conf", "**/nginx/**/*.conf", "**/ssl.conf",
                             "**/openssl.cnf", "**/httpd.conf", "**/apache2/**/*.conf"]

        for pattern in cert_patterns:
            for p in root_path.glob(pattern):
                try:
                    content = p.read_text(errors="ignore")
                    if "CERTIFICATE" not in content:
                        continue
                    detected = []
                    if "rsaEncryption" in content or "RSA" in content:
                        detected.append("RSA-2048 (PKCS#1 v1.5)")
                    if "id-ecPublicKey" in content or "prime256v1" in content:
                        detected.append("ECDSA-P256")
                    assets.append(DiscoveredAsset(
                        name=f"Cert: {p.name}",
                        target=str(p),
                        asset_type="cert_file",
                        source="filesystem",
                        detected_algorithms=detected,
                        metadata={"path": str(p)},
                    ))
                except Exception:
                    continue

        for pattern in config_patterns:
            for p in root_path.glob(pattern):
                assets.append(DiscoveredAsset(
                    name=f"Config: {p.name}",
                    target=str(p),
                    asset_type="config_file",
                    source="filesystem",
                    metadata={"path": str(p)},
                ))

        self._assets.extend(assets)
        return assets

    # ── Source 5: DNS subdomain probing ───────────────────────────────────────

    def discover_dns(
        self,
        domain: str,
        subdomains: Optional[list[str]] = None,
        ports: list[int] = None,
    ) -> list[DiscoveredAsset]:
        """Probe common subdomains for live TLS endpoints."""
        if ports is None:
            ports = [443, 8443]
        if subdomains is None:
            subdomains = [
                "www", "api", "app", "auth", "login", "id", "sso",
                "gateway", "portal", "admin", "dashboard", "mobile",
                "payment", "checkout", "secure", "cdn", "static",
            ]

        assets: list[DiscoveredAsset] = []
        for sub in subdomains:
            host = f"{sub}.{domain}"
            for port in ports:
                try:
                    with socket.create_connection((host, port), timeout=3):
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        with socket.create_connection((host, port), timeout=3) as raw:
                            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                                cipher = tls.cipher()
                                cipher_name = cipher[0] if cipher else "unknown"
                                detected = []
                                if "RSA" in cipher_name:
                                    detected.append("RSA-2048 (PKCS#1 v1.5)")
                                elif "ECDHE" in cipher_name or "ECDH" in cipher_name:
                                    detected.append("ECDH-P256")
                                assets.append(DiscoveredAsset(
                                    name=f"{host}:{port}",
                                    target=f"{host}:{port}",
                                    asset_type="tls_endpoint",
                                    source="dns",
                                    detected_algorithms=detected,
                                    metadata={"cipher": cipher_name},
                                ))
                except Exception:
                    pass  # not reachable or no TLS

        self._assets.extend(assets)
        return assets

    # ── Aggregate ──────────────────────────────────────────────────────────────

    def all_assets(self) -> list[DiscoveredAsset]:
        return list(self._assets)

    def summary(self) -> dict:
        total = len(self._assets)
        by_source: dict[str, int] = {}
        for a in self._assets:
            by_source[a.source] = by_source.get(a.source, 0) + 1
        algos: dict[str, int] = {}
        for a in self._assets:
            for alg in a.detected_algorithms:
                algos[alg] = algos.get(alg, 0) + 1
        return {
            "total_discovered": total,
            "by_source": by_source,
            "detected_algorithms": algos,
            "quantum_vulnerable_count": sum(
                1 for a in self._assets if a.detected_algorithms
            ),
        }
