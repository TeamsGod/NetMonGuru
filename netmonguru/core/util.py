"""Small helpers shared by the modules that write to the user's home."""

from __future__ import annotations

import os
from pathlib import Path


def give_back(*paths) -> None:
    """When running under ``sudo``, hand files we created back to the user.

    macOS ``sudo`` keeps ``$HOME``, so config and cache land in the real
    user's home - but owned by root, which would make them unwritable for the
    next run without sudo.
    """
    try:
        if os.geteuid() != 0:
            return
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
    except (KeyError, ValueError, AttributeError):
        return
    for p in paths:
        try:
            p = Path(p)
            os.chown(p, uid, gid)
            # parents we may have created: only ones named netmonguru*
            for parent in p.parents:
                if not parent.name.startswith("netmonguru"):
                    break
                os.chown(parent, uid, gid)
        except OSError:
            pass
