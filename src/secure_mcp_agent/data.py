"""Small synthetic dataset; no customer or production data."""

from __future__ import annotations

from copy import deepcopy


_SEED_INCIDENTS = {
    "INC-1001": {
        "id": "INC-1001",
        "title": "Checkout latency elevated",
        "status": "open",
        "severity": "high",
        "owner": "payments-oncall",
    },
    "INC-1002": {
        "id": "INC-1002",
        "title": "Reporting export delayed",
        "status": "investigating",
        "severity": "medium",
        "owner": "data-platform",
    },
    "INC-1003": {
        "id": "INC-1003",
        "title": "Resolved login alert",
        "status": "resolved",
        "severity": "low",
        "owner": "identity-team",
    },
}

INCIDENTS = deepcopy(_SEED_INCIDENTS)

SERVICE_STATUS = {
    "billing-api": {"status": "operational", "latency_ms": 83},
    "checkout-api": {"status": "degraded", "latency_ms": 481},
    "reporting-api": {"status": "operational", "latency_ms": 126},
}


def reset_data() -> None:
    INCIDENTS.clear()
    INCIDENTS.update(deepcopy(_SEED_INCIDENTS))

