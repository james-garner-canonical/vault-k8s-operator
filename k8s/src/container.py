#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Container abstraction for the Vault charm."""

from typing import TextIO

from ops import Container as OpsContainer
from ops.pebble import PathError
from vault.vault_managers import WorkloadBase


class Container(WorkloadBase):
    """Adapter class that wraps ops.Container into WorkloadBase."""

    def __init__(self, container: OpsContainer):
        self._container = container

    def __getattr__(self, name: str):
        """Delegate all unknown attributes to the container."""
        return getattr(self._container, name)

    def exists(self, path: str) -> bool:
        """Check if a file exists in the workload."""
        return self._container.exists(path=path)

    def pull(self, path: str) -> TextIO:
        """Read file from the workload."""
        return self._container.pull(path=path)

    def push(self, path: str, source: str) -> None:
        """Write file to the workload."""
        self._container.push(path=path, source=source)

    def make_dir(self, path: str) -> None:
        """Create directory in the workload."""
        self._container.make_dir(path=path)

    def remove_path(self, path: str, recursive: bool = False) -> None:
        """Remove file or directory from the workload."""
        try:
            self._container.remove_path(path=path, recursive=recursive)
        except PathError as e:
            # Rebrand PathError to ValueError for consistency with the machine
            # implementation. The description of PathError satisfies the
            # definition of ValueError.
            raise ValueError(e) from e

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
