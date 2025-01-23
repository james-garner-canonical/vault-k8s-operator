#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Container abstraction for the Vault charm."""

from charms.vault_k8s.v0.vault_managers import WorkloadBase
from ops import Container as OpsContainer


class Container(WorkloadBase):
    """Adapter class that wraps ops.Container into WorkloadBase."""

    _container: OpsContainer  # can't be None, unlike in file_ops.FileOps

    def __init__(self, container: OpsContainer):
        super().__init__(container)

    def __getattr__(self, name: str):
        """Delegate all unknown attributes to the container."""
        return getattr(self._container, name)

    def send_signal(self, signal: int, process: str) -> None:
        """Send a signal to a process in the workload."""
        self._container.send_signal(signal, process)

    def restart(self, process: str) -> None:
        """Restart the vault service."""
        self._container.restart(process)

    def stop(self, process: str) -> None:
        """Stop the workload."""
        self._container.stop(process)

    def is_accessible(self) -> bool:
        """Check if we can connect to pebble."""
        return self._container.can_connect()
