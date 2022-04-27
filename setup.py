#!/usr/bin/env python
# -*- coding: latin-1 -*-
#
# Copyright 2022 Vrije Universiteit Brussel
#
# This file is part of vsc-filesystem-oceanstor,
# originally created by the HPC team of Vrij Universiteit Brussel (http://hpc.vub.be),
# with support of Vrije Universiteit Brussel (http://www.vub.be),
# the Flemish Supercomputer Centre (VSC) (https://www.vscentrum.be),
# the Flemish Research Foundation (FWO) (http://www.fwo.be/en)
# and the Department of Economy, Science and Innovation (EWI) (http://www.ewi-vlaanderen.be/en).
#
# https://github.com/vub-hpc/vsc-filesystem-oceanstor
#
# vsc-filesystem-oceanstor is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation v2.
#
# vsc-filesystem-oceanstor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with vsc-manage.  If not, see <http://www.gnu.org/licenses/>.
#
##
"""
vsc-filesystem-oceanstor base distribution setup.py

@author: Alex Domingo (Vrije Universiteit Brussel)
"""

import vsc.install.shared_setup as shared_setup
from vsc.install.shared_setup import ad

install_requires = [
    'vsc-filesystems',
]

if sys.version_info < (3, 3):
    # Backport of the 3.3+ ipaddress module
    install_requires.append('ipaddress')

PACKAGE = {
    'version': '0.5.0',
    'author': [ad],
    'maintainer': [ad],
    'setup_requires': ['vsc-install'],
    'install_requires': install_requires,
}


if __name__ == '__main__':
    shared_setup.action_target(PACKAGE)
