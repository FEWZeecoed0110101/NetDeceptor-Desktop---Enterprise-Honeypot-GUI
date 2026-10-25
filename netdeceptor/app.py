"""Backward-compatible launcher for NetDeceptor.

Implementation is split into the netdeceptor package by responsibility.
"""
from netdeceptor.compat import *
from netdeceptor.config import *
from netdeceptor.database import *
from netdeceptor.services import *
from netdeceptor.engine import *
from netdeceptor.reports import *
from netdeceptor.dashboard import *
from netdeceptor.cli import main

if __name__ == "__main__":
    sys.exit(main())
