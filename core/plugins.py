"""Plugin system — load community payload packs and external modules.

Supports:
- External payload packs: directories of YAML files merged with built-in payloads
- Payload pack manifests: pack.yaml describing the pack metadata
"""

from __future__ import annotations

import pathlib
from typing import Any

import yaml

from core.logger import ValkLogger


class PayloadPack:
    """A community payload pack loaded from an external directory."""

    def __init__(self, path: pathlib.Path):
        self.path = path
        self.name: str = path.name
        self.version: str = "0.0.0"
        self.author: str = "unknown"
        self.description: str = ""
        self.payload_files: list[pathlib.Path] = []
        self._load_manifest()
        self._discover_payloads()

    def _load_manifest(self) -> None:
        """Load pack.yaml manifest if present."""
        manifest = self.path / "pack.yaml"
        if not manifest.exists():
            return
        try:
            with open(manifest, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            self.name = data.get("name", self.name)
            self.version = data.get("version", self.version)
            self.author = data.get("author", self.author)
            self.description = data.get("description", self.description)
        except Exception:
            pass

    def _discover_payloads(self) -> None:
        """Find all YAML payload files in the pack directory."""
        self.payload_files = sorted(
            p for p in self.path.glob("*.yaml")
            if p.name != "pack.yaml"
        )

    def load_payload(self, filename: str) -> Any:
        """Load a specific payload file from this pack."""
        path = self.path / filename
        if not path.exists():
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception:
            return {}


class PluginLoader:
    """Discover and load external payload packs."""

    def __init__(self, log: ValkLogger):
        self.log = log
        self.packs: list[PayloadPack] = []

    def load_packs(self, directories: list[str]) -> None:
        """Load payload packs from a list of directory paths."""
        for dir_path in directories:
            path = pathlib.Path(dir_path).resolve()
            if not path.is_dir():
                self.log.warning(f"payload pack directory not found: {dir_path}", module="plugins")
                continue

            # Check if directory itself is a pack (has YAML files)
            yamls = list(path.glob("*.yaml"))
            if yamls:
                pack = PayloadPack(path)
                self.packs.append(pack)
                self.log.info(
                    "plugins",
                    f"loaded pack: {pack.name} v{pack.version} "
                    f"({len(pack.payload_files)} payloads)",
                )
                continue

            # Otherwise, check subdirectories as individual packs
            for subdir in sorted(path.iterdir()):
                if subdir.is_dir() and list(subdir.glob("*.yaml")):
                    pack = PayloadPack(subdir)
                    self.packs.append(pack)
                    self.log.info(
                        "plugins",
                        f"loaded pack: {pack.name} v{pack.version} "
                        f"({len(pack.payload_files)} payloads)",
                    )

    def get_merged_payloads(self, filename: str, builtin: Any) -> Any:
        """Merge payloads from all packs with built-in payloads.

        For YAML files with a top-level list key (e.g. 'techniques', 'scenarios'),
        pack entries are appended. For other structures, pack data is ignored.

        Args:
            filename: The payload filename (e.g. 'jailbreaks.yaml')
            builtin: The built-in payload data already loaded

        Returns:
            Merged payload data
        """
        if not self.packs:
            return builtin

        if not isinstance(builtin, dict):
            return builtin

        merged = dict(builtin)

        for pack in self.packs:
            pack_data = pack.load_payload(filename)
            if not isinstance(pack_data, dict):
                continue

            for key, value in pack_data.items():
                if isinstance(value, list) and key in merged and isinstance(merged[key], list):
                    # Append pack entries, tagged with pack name
                    for item in value:
                        if isinstance(item, dict):
                            item["_pack"] = pack.name
                        merged[key].append(item)
                    self.log.debug(
                        "plugins",
                        f"merged {len(value)} entries from {pack.name}/{filename}:{key}",
                    )

        return merged
