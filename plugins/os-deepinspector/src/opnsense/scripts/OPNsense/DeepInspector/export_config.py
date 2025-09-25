#!/usr/local/bin/python3
"""
DeepInspector OPNsense Configuration Exporter - Full Import
-----------------------------------------------------------
Reads the OPNsense system configuration (config.xml), parses
all DeepInspector plugin settings, and exports them to a JSON
file for the DPI engine.

Features:
- Full support for <general>, <protocols>, <detection>, <advanced>
- Boolean and integer normalization
- Handles missing fields gracefully
- Creates output directories automatically
- Ready for cron or automation tasks

Author: Pierpaolo Casati
Version: 1.0
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigExporter:
    """
    Exports DeepInspector configuration from OPNsense config.xml
    to a JSON file for the DPI engine.
    """

    def __init__(self,
                 source_xml: str = "/conf/config.xml",
                 target_json: str = "/usr/local/etc/deepinspector/config.json"):
        """
        Initialize the exporter.

        Args:
            source_xml: Path to the OPNsense XML configuration file.
            target_json: Path to the output JSON configuration file.
        """
        self.source_path = Path(source_xml)
        self.target_path = Path(target_json)

    def _convert_value(self, value: Optional[str]) -> Any:
        """
        Convert XML string values to Python types.

        - '0' or '1' → bool
        - Numeric strings → int
        - Otherwise → str

        Args:
            value: XML text value

        Returns:
            Converted Python object
        """
        if value is None:
            return ""
        val = value.strip()
        if val in ("0", "1"):
            return val == "1"
        if val.isdigit():
            return int(val)
        return val

    def _extract_section(self, parent: ET.Element, section_name: str) -> Dict[str, Any]:
        """
        Extract key-value pairs from a given XML section.

        Args:
            parent: Parent XML node containing the section
            section_name: Name of the child node to extract

        Returns:
            Dictionary of settings for that section
        """
        section_data: Dict[str, Any] = {}
        node = parent.find(section_name)
        if node is not None:
            for child in node:
                section_data[child.tag] = self._convert_value(child.text)
        return section_data

    def export(self) -> bool:
        """
        Perform the export operation.

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.source_path.exists():
                print(f"OPNsense config file not found: {self.source_path}")
                return False

            # Parse XML configuration
            tree = ET.parse(self.source_path)
            root = tree.getroot()

            # Locate the DeepInspector node
            dpi_node = root.find(".//OPNsense/DeepInspector")
            if dpi_node is None:
                print("DeepInspector configuration not found in config.xml")
                return False

            # Build configuration dictionary
            config: Dict[str, Dict[str, Any]] = {
                "general": self._extract_section(dpi_node, "general"),
                "protocols": self._extract_section(dpi_node, "protocols"),
                "detection": self._extract_section(dpi_node, "detection"),
                "advanced": self._extract_section(dpi_node, "advanced"),
            }

            # Ensure destination directory exists
            self.target_path.parent.mkdir(parents=True, exist_ok=True)

            # Write configuration to JSON
            with self.target_path.open("w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)

            print(f"DeepInspector configuration exported to {self.target_path}")
            return True

        except Exception as exc:
            print(f"Error exporting configuration: {exc}")
            return False


def main() -> None:
    """
    CLI entry point.
    Creates a ConfigExporter instance and runs the export.
    """
    exporter = ConfigExporter()
    success = exporter.export()
    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
