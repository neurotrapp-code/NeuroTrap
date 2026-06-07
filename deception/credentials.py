"""Day 25 — Fake credential & data generator.

Produces believable usernames, passwords, emails, AWS-style keys, generic API
keys, a private-key stub and seeded fake DB tables to populate honeypot
filesystems and decoy databases.

Uses the ``faker`` library when installed for maximum realism; otherwise falls
back to bundled word/name lists so the engine works with stdlib only. The
generated AWS keys are intended to be wired to canarytokens in Week 6 so any use
raises an out-of-band alert.
"""
from __future__ import annotations

import random
import string
from dataclasses import dataclass, field
from typing import Dict, List

try:
    from faker import Faker
    _FAKE = Faker()
    _HAVE_FAKER = True
except Exception:                       # pragma: no cover - optional dep
    _FAKE = None
    _HAVE_FAKER = False

# Credentials botnets actually spray (used when credential_profile.common).
COMMON_PASSWORDS = [
    "123456", "admin", "root", "password", "12345678", "toor", "1234",
    "letmein", "qwerty", "admin123", "P@ssw0rd", "changeme",
]
_FALLBACK_FIRST = ["james", "maria", "ahmed", "sara", "liang", "omar", "nina",
                   "victor", "leila", "tom", "priya", "hassan"]
_FALLBACK_LAST = ["khan", "smith", "garcia", "wang", "haddad", "jones", "patel",
                  "rossi", "novak", "abadi", "kim", "silva"]
_SERVICE_USERS = ["deploy", "jenkins", "backup", "postgres", "www-data",
                  "gitlab-runner", "ec2-user", "ubuntu"]


def _rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(random.choice(alphabet) for _ in range(n))


@dataclass
class CredentialSet:
    users: List[Dict[str, str]] = field(default_factory=list)     # {username,password}
    emails: List[str] = field(default_factory=list)
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    api_keys: Dict[str, str] = field(default_factory=dict)
    db_password: str = ""
    jwt_secret: str = ""
    ssh_private_key: str = ""
    db_tables: Dict[str, List[Dict]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        # never echo the full key material into logs/dashboards verbatim length
        return d


class CredentialGenerator:
    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)
        if seed is not None:
            random.seed(seed)
            if _HAVE_FAKER:
                Faker.seed(seed)

    # -- atoms -------------------------------------------------------------
    def username(self) -> str:
        if _HAVE_FAKER:
            return _FAKE.user_name()
        return f"{self.rng.choice(_FALLBACK_FIRST)}.{self.rng.choice(_FALLBACK_LAST)}"

    def password(self, weak: bool = False, common: bool = False) -> str:
        if common:
            return self.rng.choice(COMMON_PASSWORDS)
        if weak:
            return self.rng.choice(_FALLBACK_FIRST).capitalize() + str(self.rng.randint(1, 999))
        # strong-ish realistic password
        return (_rand(4, string.ascii_uppercase) + _rand(6, string.ascii_lowercase)
                + str(self.rng.randint(10, 99)) + self.rng.choice("!@#$%&*"))

    def email(self, domain: str = "globex-corp.com") -> str:
        if _HAVE_FAKER:
            return _FAKE.email()
        return f"{self.username().replace('.', '')}@{domain}"

    def aws_access_key_id(self) -> str:
        return "AKIA" + _rand(16, string.ascii_uppercase + string.digits)

    def aws_secret(self) -> str:
        return _rand(40, string.ascii_letters + string.digits + "+/")

    def api_key(self, prefix: str = "sk") -> str:
        return f"{prefix}_live_{_rand(32)}"

    def ssh_private_key_stub(self) -> str:
        body = "\n".join(_rand(64) for _ in range(6))
        return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                f"{body}\n-----END OPENSSH PRIVATE KEY-----\n")

    # -- fake DB -----------------------------------------------------------
    def customer_table(self, rows: int = 25) -> List[Dict]:
        out = []
        for i in range(rows):
            name = (_FAKE.name() if _HAVE_FAKER
                    else f"{self.rng.choice(_FALLBACK_FIRST).title()} "
                         f"{self.rng.choice(_FALLBACK_LAST).title()}")
            out.append({
                "id": 1000 + i,
                "name": name,
                "email": self.email(),
                "card_last4": f"{self.rng.randint(0, 9999):04d}",
                "balance": round(self.rng.uniform(10, 9000), 2),
            })
        return out

    def employee_table(self, rows: int = 15) -> List[Dict]:
        roles = ["engineer", "manager", "analyst", "admin", "sales"]
        out = []
        for i in range(rows):
            out.append({
                "emp_id": f"E{2000 + i}",
                "username": self.username(),
                "role": self.rng.choice(roles),
                "salary": self.rng.randint(40000, 180000),
            })
        return out

    # -- bundles -----------------------------------------------------------
    def generate_set(self, count: int = 4, weak: bool = False, common: bool = False,
                     aws: bool = False, fake_db: bool = False,
                     private_keys: bool = False) -> CredentialSet:
        cs = CredentialSet()
        # always include a couple of recognizable service accounts
        pool = list(_SERVICE_USERS)
        self.rng.shuffle(pool)
        for i in range(max(count, 1)):
            uname = pool[i] if i < len(pool) else self.username()
            cs.users.append({
                "username": uname,
                "password": self.password(weak=weak, common=common),
            })
        cs.emails = [self.email() for _ in range(min(count, 5))]
        cs.db_password = self.password()
        cs.jwt_secret = _rand(48)
        cs.api_keys = {
            "stripe": self.api_key("sk"),
            "sendgrid": "SG." + _rand(22) + "." + _rand(43),
        }
        if aws:
            cs.aws_access_key_id = self.aws_access_key_id()
            cs.aws_secret_access_key = self.aws_secret()
        if private_keys:
            cs.ssh_private_key = self.ssh_private_key_stub()
        if fake_db:
            cs.db_tables = {
                "customers": self.customer_table(),
                "employees": self.employee_table(),
            }
        return cs
