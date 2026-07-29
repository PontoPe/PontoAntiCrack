"""Lazily-created, per-invocation-cached boto3 clients.

boto3 ships no type information in the Lambda runtime, so the client objects are
``Any`` at this seam and nowhere else — see docs/architecture.md ADR-006.
"""

from __future__ import annotations

from typing import Any

import boto3


class AwsClients:
    """Client factory with a cache, so a warm container reuses connections."""

    def __init__(self, session: Any | None = None, region_name: str | None = None) -> None:
        self._session: Any = session if session is not None else boto3.session.Session()
        self._region_name = region_name
        self._clients: dict[str, Any] = {}
        self._resources: dict[str, Any] = {}

    def client(self, name: str) -> Any:
        if name not in self._clients:
            self._clients[name] = self._session.client(name, region_name=self._region_name)
        return self._clients[name]

    def resource(self, name: str) -> Any:
        if name not in self._resources:
            self._resources[name] = self._session.resource(name, region_name=self._region_name)
        return self._resources[name]

    @property
    def s3(self) -> Any:
        return self.client("s3")

    @property
    def ec2(self) -> Any:
        return self.client("ec2")

    @property
    def iam(self) -> Any:
        return self.client("iam")

    @property
    def secretsmanager(self) -> Any:
        return self.client("secretsmanager")

    def table(self, name: str) -> Any:
        return self.resource("dynamodb").Table(name)
