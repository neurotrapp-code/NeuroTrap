"""CADN Week 5 — Management API + dashboard backend (Layer 5, portal half).

A Flask app that serves the real-time dashboard and a JWT-protected REST API. All
endpoints read from the LIVE event store the pipeline fills from real honeypot/IDS
traffic — there is no demo/sample data source.
"""
from .app import create_app

__all__ = ["create_app"]
