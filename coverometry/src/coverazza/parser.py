from __future__ import annotations
import sys
import os
import struct
from dataclasses import dataclass

DRCOV_VERSION_TAG = "DRCOV VERSION"
DRCOV_SUPPORTED_VERSIONS = [2]
DRCOV_FLAVOR_TAG = "DRCOV FLAVOR"
DRCOV_SUPPORTED_FLAVORS = ["FRIDA", "DRCOV-64"]
DRCOV_MODULE_TABLE_TAG = "MODULE TABLE"
DRCOV_MODULE_TABLE_SUPORTED_VERSIONS = [2]
DRCOV_COLUMNS_TAG = "COLUMNS"
DRCOV_BB_TABLE_TAG = "BB TABLE"


class CoverazzaParsingException(Exception):
    pass


@dataclass
class DrCov2MT2Entry:
    """Class representing a DrCov module table row for DrCov version 2 with
    module table version 2."""

    id: int
    base: int
    end: int
    entry: int
    checksum: int
    timestamp: int
    path: str
    bbs: list[int]


def parse_drcov(f) -> list[DrCov2MT2Entry]:

    # parse version
    line = f.readline().decode()
    tag, val = line.split(": ")

    if not DRCOV_VERSION_TAG == tag.upper():
        raise CoverazzaParsingException("Version tag not found.")

    if int(val) not in DRCOV_SUPPORTED_VERSIONS:
        raise CoverazzaParsingException(f"Version {val} not supported.")

    # parse flavor
    line = f.readline().decode()
    tag, flavor = line.split(": ")

    if not DRCOV_FLAVOR_TAG == tag.upper():
        raise CoverazzaParsingException("Flavor tag not found.")

    if flavor.strip().upper() not in DRCOV_SUPPORTED_FLAVORS:
        raise CoverazzaParsingException(f"Flavor {flavor} not supported.")

    # parse moduel table meta
    line = f.readline().decode()
    tag, mt_vals = line.split(": ")

    if not DRCOV_MODULE_TABLE_TAG == tag.upper():
        raise CoverazzaParsingException("Module table tag not found.")

    mt_meta_raw: list[str] = mt_vals.split(", ")
    mt_meta: dict[str, str] = {}
    for mt_entry in mt_meta_raw:
        k, v = mt_entry.split(" ")
        mt_meta[k] = int(v)

    if "version" not in mt_meta:
        raise CoverazzaParsingException("Module table version not found.")

    if mt_meta["version"] not in DRCOV_MODULE_TABLE_SUPORTED_VERSIONS:
        raise CoverazzaParsingException("Module table version not supported.")

    if "count" not in mt_meta:
        raise CoverazzaParsingException("Module table count not found.")

    # parse columns
    line = f.readline().decode()
    tag, col_names = line.split(": ")

    if not DRCOV_COLUMNS_TAG == tag.upper():
        raise CoverazzaParsingException("Columns tag not found.")

    # sanity check
    entry_keys = [
        k.strip() for k in DrCov2MT2Entry.__dict__["__annotations__"].keys()
    ]
    for idx, col_name in enumerate(
        [cn.strip() for cn in col_names.split(", ")]
    ):
        if idx >= len(entry_keys):
            raise CoverazzaParsingException(
                "DrCov Module Table format mismatch"
            )

        if entry_keys[idx] != col_name:
            import ipdb

            ipdb.set_trace()
            raise CoverazzaParsingException(
                f"DrCov Module Table format mismatch: {entry_keys[idx]} != {col_name}"
            )

    mt_rows: list[DrCov2MT2Entry] = []
    for idx in range(mt_meta["count"]):
        mt_row = f.readline().decode().strip().split(", ")
        entry = DrCov2MT2Entry(
            int(mt_row[0].strip()),
            int(mt_row[1].strip(), 16),
            int(mt_row[2].strip(), 16),
            int(mt_row[3].strip(), 16),
            int(mt_row[4].strip(), 16),
            int(mt_row[5].strip(), 16),
            mt_row[6],
            [],
        )
        mt_rows.append(entry)

    # parse BB Table
    line = f.readline().decode()
    tag, bb_count = line.split(": ")

    if not DRCOV_BB_TABLE_TAG == tag.upper():
        raise CoverazzaParsingException("BB table tag not found.")

    bb_count = int(bb_count.strip().split(" ")[0])
    for idx in range(bb_count):
        start = struct.unpack("<I", f.read(4))[0]
        sz = struct.unpack("<H", f.read(2))[0]
        mod_id = struct.unpack("<H", f.read(2))[0]
        mt_rows[mod_id].bbs.append(start)

    return mt_rows


def parse(drcov: str):

    mt_rows = None
    with open(drcov, "rb") as f:
        mt_rows = parse_drcov(f)
    return mt_rows
