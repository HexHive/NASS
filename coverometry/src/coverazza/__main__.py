from __future__ import annotations
import sys
import os
from . import parser


def usage():
    print(f"{sys.argv[0]} <drcov>")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        exit()

    drcov = sys.argv[1]
    if not os.path.exists(drcov):
        usage()
        exit()

    parser.parse(drcov)
