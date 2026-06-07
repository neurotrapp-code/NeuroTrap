"""Week 4 — Deception Engine tests."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from deception import (DeceptionEngine, CredentialGenerator, FilesystemFactory,
                       load_template, classify_skill_tier, build_servers)


# --- personalization -----------------------------------------------------
def test_personalization_tiers():
    assert classify_skill_tier("Reconnaissance", threat_score=10) == "beginner"
    assert classify_skill_tier("Bot Enrollment") == "bot"
    assert classify_skill_tier("Cryptomining") == "bot"
    assert classify_skill_tier("Lateral Movement") == "advanced"
    assert classify_skill_tier("Credential Harvesting") == "advanced"
    # high cadence forces bot regardless of intent
    assert classify_skill_tier("Reconnaissance", cmds_per_second=5.0) == "bot"
    # dangerous recon escalates
    assert classify_skill_tier("Reconnaissance", threat_score=80) == "advanced"


# --- templates -----------------------------------------------------------
def test_templates_load_and_have_services():
    for name in ("beginner", "bot", "advanced"):
        t = load_template(name)
        assert t["name"] == name
        assert len(t["services"]) >= 1
        assert "ttl_seconds" in t


# --- credentials ---------------------------------------------------------
def test_credential_generator_shapes():
    cs = CredentialGenerator(seed=1).generate_set(
        count=5, aws=True, fake_db=True, private_keys=True)
    assert len(cs.users) == 5
    assert all("username" in u and "password" in u for u in cs.users)
    assert cs.aws_access_key_id.startswith("AKIA")
    assert cs.ssh_private_key.startswith("-----BEGIN")
    assert "customers" in cs.db_tables and len(cs.db_tables["customers"]) > 0


def test_common_passwords_for_bots():
    from deception.credentials import COMMON_PASSWORDS
    cs = CredentialGenerator(seed=2).generate_set(count=6, weak=True, common=True)
    assert any(u["password"] in COMMON_PASSWORDS for u in cs.users)


# --- filesystem factory --------------------------------------------------
def test_corporate_filesystem_contains_secrets():
    creds = CredentialGenerator(seed=3).generate_set(
        count=4, aws=True, fake_db=True, private_keys=True)
    with tempfile.TemporaryDirectory() as d:
        manifest = FilesystemFactory().build(load_template("advanced"), creds, d)
        assert "/opt/app/.env" in manifest
        assert "/root/.aws/credentials" in manifest
        assert "/root/.ssh/id_rsa" in manifest
        # files actually exist on disk
        assert all(os.path.exists(p) for p in manifest.values())
        with open(manifest["/opt/app/.env"]) as f:
            assert "DB_PASSWORD" in f.read()


def test_minimal_filesystem_has_no_aws():
    creds = CredentialGenerator(seed=4).generate_set(count=2, weak=True)
    with tempfile.TemporaryDirectory() as d:
        manifest = FilesystemFactory().build(load_template("beginner"), creds, d)
        assert "/etc/passwd" in manifest
        assert "/root/.aws/credentials" not in manifest


# --- fake servers --------------------------------------------------------
def test_build_servers_and_compose():
    servers = build_servers(load_template("advanced"), env_id="abcd1234", seed=1)
    assert {s.service for s in servers} >= {"ssh", "http", "ftp", "mysql"}
    comp = servers[0].to_compose_service()
    name = list(comp)[0]
    assert comp[name]["labels"]["cadn.role"] == "deception"


# --- full engine lifecycle ----------------------------------------------
def test_generate_and_teardown_environment():
    with tempfile.TemporaryDirectory() as d:
        eng = DeceptionEngine(workdir=d, dry_run=True, seed=9)
        env = eng.generate_environment(
            src_ip="203.0.113.7", intent="Credential Harvesting",
            threat_score=85, n_ttps=5)
        assert env.tier == "advanced"
        assert env.spawn_seconds < 30        # plan target
        assert len(eng.get_active_environments()) == 1
        assert eng.health(env.env_id)["healthy"]
        assert os.path.isdir(env.filesystem_path)

        assert eng.teardown(env.env_id)
        assert not os.path.isdir(env.filesystem_path)   # fs cleaned up
        assert all(s.status == "stopped" for s in env.servers)


def test_ttl_auto_reap():
    with tempfile.TemporaryDirectory() as d:
        eng = DeceptionEngine(workdir=d, dry_run=True, seed=9)
        env = eng.generate_environment(src_ip="203.0.113.8", intent="Reconnaissance")
        env.created_at -= env.ttl_seconds + 1            # force expiry
        reaped = eng.tick()
        assert env.env_id in reaped
        assert env.status == "torndown"


def test_session_close_reaps():
    with tempfile.TemporaryDirectory() as d:
        eng = DeceptionEngine(workdir=d, dry_run=True, seed=9)
        env = eng.generate_environment(src_ip="203.0.113.9", intent="Reconnaissance")
        eng.lifecycle.mark_session_closed(env.env_id)
        assert env.env_id in eng.tick()
