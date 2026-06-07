"""Day 24 — Fake server generator.

Each service in a template becomes a :class:`FakeServer` with a randomized but
realistic hostname, OS/service banner and version. Servers can render a
docker-compose service definition for real deployment, and ``start()``/``stop()``
drive the Docker SDK when available — otherwise they run in **dry-run** mode
(state is tracked, nothing is launched) so the engine is testable without Docker.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import docker            # optional
    _HAVE_DOCKER = True
except Exception:            # pragma: no cover - optional dep
    docker = None
    _HAVE_DOCKER = False

# Plausible hostnames by role.
_HOST_PREFIX = ["web", "app", "db", "edge", "svc", "node", "vm", "host"]
_HOST_SUFFIX = ["prod", "staging", "dc1", "use1", "core", "01", "02", "07"]

# Per-protocol container image + banner generators for dry-run realism.
_SERVICE_IMAGES = {
    "ssh": "cowrie/cowrie:latest",
    "telnet": "cowrie/cowrie:latest",
    "http": "nginx:1.24-alpine",
    "ftp": "fauria/vsftpd:latest",
    "mysql": "mysql:8.0",
}


def random_hostname(rng: random.Random) -> str:
    return f"{rng.choice(_HOST_PREFIX)}-{rng.choice(_HOST_SUFFIX)}-{rng.randint(1,99):02d}"


@dataclass
class FakeServer:
    service: str                       # ssh|telnet|http|ftp|mysql
    port: int
    hostname: str
    os_banner: str
    version: str
    image: str
    container_name: str = ""
    status: str = "created"            # created|running|stopped|error
    container_id: Optional[str] = None

    def to_compose_service(self) -> dict:
        """Render a docker-compose service fragment for this fake server."""
        return {
            self.container_name: {
                "image": self.image,
                "container_name": self.container_name,
                "hostname": self.hostname,
                "restart": "unless-stopped",
                "ports": [f"{self.port}:{self.port}"],
                "networks": ["honeypot-net"],
                "labels": {
                    "cadn.role": "deception",
                    "cadn.service": self.service,
                },
            }
        }

    def to_dict(self) -> dict:
        return {
            "service": self.service, "port": self.port, "hostname": self.hostname,
            "os_banner": self.os_banner, "version": self.version,
            "container_name": self.container_name, "status": self.status,
        }

    # -- runtime control ---------------------------------------------------
    def start(self, dry_run: bool = True):
        if dry_run or not _HAVE_DOCKER:
            self.status = "running"
            return self
        try:                                              # pragma: no cover
            client = docker.from_env()
            c = client.containers.run(
                self.image, name=self.container_name, hostname=self.hostname,
                detach=True, network="honeypot-net",
                ports={f"{self.port}/tcp": self.port},
                labels={"cadn.role": "deception", "cadn.service": self.service})
            self.container_id = c.id
            self.status = "running"
        except Exception:
            self.status = "error"
        return self

    def stop(self, dry_run: bool = True):
        if dry_run or not _HAVE_DOCKER or not self.container_id:
            self.status = "stopped"
            return self
        try:                                              # pragma: no cover
            client = docker.from_env()
            c = client.containers.get(self.container_id)
            c.remove(force=True)
        except Exception:
            pass
        self.status = "stopped"
        return self


def build_servers(template: dict, env_id: str, seed: Optional[int] = None) -> List[FakeServer]:
    """Instantiate one :class:`FakeServer` per service in the template."""
    rng = random.Random(seed)
    os_banner = template.get("os_banner", "Linux")
    servers: List[FakeServer] = []
    for i, svc in enumerate(template.get("services", [])):
        proto = svc["proto"]
        host = random_hostname(rng)
        servers.append(FakeServer(
            service=proto,
            port=int(svc["port"]),
            hostname=host,
            os_banner=os_banner,
            version=svc.get("version", ""),
            image=_SERVICE_IMAGES.get(proto, "alpine:latest"),
            container_name=f"cadn-decoy-{env_id[:8]}-{proto}-{i}",
        ))
    return servers
