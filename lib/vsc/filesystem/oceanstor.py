##
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
Interface for Huawei Pacific OceanStor

@author: Alex Domingo (Vrije Universiteit Brussel)
"""

from __future__ import print_function
from future.utils import with_metaclass

import json
import os
import ssl

from vsc.filesystem.posix import PosixOperations
from vsc.utils import fancylogger
from vsc.utils.patterns import Singleton
from vsc.utils.rest import Client, RestClient
from vsc.utils.py2vs3 import HTTPError, HTTPSHandler, build_opener

OCEANSTOR_API_PATH = ['api', 'v2']


class OceanStorClient(Client):
    """Client for OceanStor REST API"""

    def __init__(self, *args, ssl_verify=True, **kwargs):
        """Wrapper for Client.__init__() allowing to disable SSL certificate verification"""
        super(OceanStorClient, self).__init__(*args, **kwargs)

        # X-Auth-Token header
        self.x_auth_header = None

        if ssl_verify is False:
            # Disable verification of SSL certificates
            nossl_context = ssl._create_unverified_context()
            nosslHandler = HTTPSHandler(context=nossl_context)
            self.opener = build_opener(nosslHandler)
            fancylogger.getLogger().warning("Verification of SSL certificates disabled by request!")

    def request(self, *args, **kwargs):
        """
        Wrapper for Client.request() with HTTP error and exit code handling
        Injects X-Auth-Token headers into teh query if present
        """
        # Inject X-Auth-Token into headers (args=(method, url, body, headers))
        args = list(args)
        if args[3] is None:
            args[3] = {}
        if self.x_auth_header:
            args[3].update(self.x_auth_header)

        # Execute request catching any HTTPerror
        try:
            status, response = super(OceanStorClient, self).request(*args, **kwargs)
        except HTTPError as err:
            errmsg = "OceanStor query failed with HTTP error: %s (%s)" % (err.reason, err.code)
            fancylogger.getLogger().error(errmsg)
            raise

        # Query exit code is found inside the result entry
        try:
            result = response['result']
        except (KeyError, TypeError) as err:
            errmsg = "OceanStor response lacks resulting status: %s" % response
            fancylogger.getLogger().raiseException(errmsg, exception=err.__class__)

        try:
            exit_code = result['code']
        except TypeError as err:
            # Some queries generate a response with an int result
            # e.g. GET 'data_service/storagepool'
            exit_code = result
            ec_msg = "%s" % result
        else:
            ec_msg_desc = result['description']
            if 'suggestion' in result:
                ec_msg_desc += ' ' + result['suggestion']
            ec_msg = "%s (%s)" % (result['code'], ec_msg_desc)

        ec_full_msg = "OceanStor query returned exit code: %s" % ec_msg
        if exit_code != 0:
            fancylogger.getLogger().raiseException(ec_full_msg, exception=RuntimeError)
        else:
            fancylogger.getLogger().debug(ec_full_msg)

        return status, response

    def get_x_auth_token(self, password, username=None):
        """Request authetication token"""
        if not username:
            username = self.username

        query_url = os.path.join('aa', 'sessions')
        payload = {
            'user_name': username,
            'password': password,
        }

        status, response = self.post(query_url, body=payload)
        fancylogger.getLogger().debug("Request for X-Auth-Token got reponse status: %s", status)

        try:
            token = response['data']['x_auth_token']
        except AttributeError as err:
            errmsg = "X-Auth-Token not found in response from OceanStor"
            fancylogger.getLogger().raiseException(errmsg, exception=AttributeError)
        else:
            self.x_auth_header = {'X-Auth-Token': token}
            fancylogger.getLogger().info("OceanStor authentication switched to X-Auth-Token for this session")

        return True


class OceanStorRestClient(RestClient):
    def __init__(self, *args, **kwargs):
        """Create client for OceanStor with given arguments"""
        self.client = OceanStorClient(*args, **kwargs)


class OceanStorOperations(with_metaclass(Singleton, PosixOperations)):
    def __init__(self, url, username=None, password=None):
        """Initialize REST client and request authentication token"""
        super(OceanStorOperations, self).__init__()

        self.log = fancylogger.getLogger()

        self.storagepools = None
        self.filesystems = None
        self.filesets = None

        # OceanStor API URL
        self.url = os.path.join(url, *OCEANSTOR_API_PATH)
        self.log.info("URL of OceanStor server: %s", self.url)

        # Open API session with user/password
        if username is None:
            self.log.raiseException("Missing OceanStor username", TypeError)
        if password is None:
            self.log.raiseException("Missing password for OceanStor user: %s" % username, TypeError)

        self.session = OceanStorRestClient(self.url, username=username, password=password, ssl_verify=False)

        # Get token for this session
        self.session.client.get_x_auth_token(password)

    def list_storage_pools(self, update=False):
        """
        List all storage pools (equivalent to devices in GPFS)

        Set self.storagepools to a convenient dict structure of the returned dict
        where the key is the storagePoolName, the value is a dict with keys:
        - storagePoolId
        - storagePoolName
        - totalCapacity
        - reductionInvolvedCapacity
        - allocatedCapacity
        - usedCapacity
        - freeCapacityRate
        - usedCapacityRate
        - status
        - progress
        - securityLevel
        - redundancyPolicy
        - numParityUnits
        - numFaultTolerance
        - compressionAlgorithm
        - deduplicationSaved
        - compressionSaved
        - deduplicationRatio
        - compressionRatio
        - dataReductionRatio
        - encryptType
        - supportEncryptForMainStorageMedia
        """
        if not update and self.storagepools:
            return self.storagepools

        # Request storage pools
        _, response = self.session.data_service.storagepool.get()
        storage_pools = [sp['storagePoolName'] for sp in response['storagePools']]
        self.log.debug("Storage pools in OceanStor: %s", ', '.join(storage_pools))

        res = dict()
        for sp in response['storagePools']:
            res.update({sp['storagePoolName']: sp})

        if len(res) == 0:
            self.log.raiseException("No storage pools found in OceanStor", RuntimeError)

        self.storagepools = res
        return res

    def list_filesystems(self):
        """
        List all filesystems.
        """
        _, response = self.session.file_service.file_systems.get()
        filesystems = [fs['name'] for fs in response['data']]
        self.log.info("List of filesystems in OceanStor: %s", ', '.join(filesystems))

