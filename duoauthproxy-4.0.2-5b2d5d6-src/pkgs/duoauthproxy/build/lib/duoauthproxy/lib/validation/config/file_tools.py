#
# Copyright (c) 2018 Duo Security
# All Rights Reserved
#

import os
from duoauthproxy.lib import util


def check_file(filename_to_check):
    """
    Check if the specified file exists and is readable.
    Args:
        filename_to_check (str):  the filename to check, relative or absolute.
            If it is a relative path, we try the check twice- once as normal,
            and once with a prepended "conf/".
    Returns:
        bool: True if the file can be opened for reading; False otherwise
    """
    try:
        # Covers absolute paths as well as relative paths with prepended conf/
        open(filename_to_check, 'r')
        return True
    except (OSError, IOError):
        try:
            # Covers relative paths without conf/ by tacking it onto filepath
            open(util.resolve_file_path(filename_to_check), 'r')
            return True
        except (OSError, IOError):
            return False


def check_directory(path):
    """ Check if a directory exists
    Args:
        path (str): Path starting at INSTALL-DIR/.
        If path begins with / then INSTALLDIR prefix is ignored
    Returns:
        bool: True if the dir exists; False otherwise
    """
    path = os.path.join(util.get_home_dir(), path)
    return os.path.isdir(path)
