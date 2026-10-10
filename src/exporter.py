"""
CSV Exporter for Network Packet Metadata.

Safely writes captured packet header attributes and protocol metadata to
standard CSV files with proper header definitions and character escaping.
Strictly excludes application payloads and sensitive authentication data.
"""

import csv
import logging
from pathlib import Path
from typing import List, Union

from src.config import CSV_FIELDNAMES, DEFAULT_OUTPUT_PATH
from src.models import PacketMetadata

logger = logging.getLogger(__name__)


def export_to_csv(
    packets: List[PacketMetadata],
    filepath: Union[str, Path] = DEFAULT_OUTPUT_PATH,
    append: bool = False,
) -> bool:
    """
    Export a list of PacketMetadata records to a CSV file.
    
    Args:
        packets: List of PacketMetadata objects to export.
        filepath: Destination file path (e.g. 'logs/captured_packets.csv').
        append: If True, appends to existing file without rewriting headers.
        
    Returns:
        bool: True if export was successful, False otherwise.
    """
    target_path = Path(filepath)

    try:
        # Ensure target directory exists
        target_path.parent.mkdir(parents=True, exist_ok=True)

        mode = "a" if (append and target_path.exists()) else "w"
        write_header = not (append and target_path.exists())

        with open(target_path, mode=mode, newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=CSV_FIELDNAMES,
                quoting=csv.QUOTE_MINIMAL,
                extrasaction="ignore",
            )

            if write_header:
                writer.writeheader()

            for pkt in packets:
                writer.writerow(pkt.to_dict())

        logger.info("Successfully exported %d packets to %s", len(packets), target_path)
        return True

    except PermissionError as p_err:
        logger.error("Permission denied when writing to CSV '%s': %s", target_path, p_err)
        print(f"\n[!] Error: Permission denied writing to '{target_path}'. Check file permissions or close open Excel instances.")
        return False
    except OSError as os_err:
        logger.error("OS error writing to CSV '%s': %s", target_path, os_err)
        print(f"\n[!] Error: Unable to write to '{target_path}': {os_err}")
        return False
    except Exception as exc:
        logger.error("Unexpected error during CSV export: %s", exc)
        print(f"\n[!] Unexpected error exporting CSV: {exc}")
        return False
