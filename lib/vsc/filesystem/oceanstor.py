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

from vsc.filesystem.posix import PosixOperations, PosixOperationError
from vsc.utils import fancylogger
from vsc.utils.patterns import Singleton
from vsc.utils.rest import Client, RestClient
from vsc.utils.py2vs3 import HTTPError, HTTPSHandler, build_opener

OCEANSTOR_API_PATH = ['api', 'v2']

# REST API cannot handle white spaces between keys and values
OCEANSTOR_JSON_SEP = (',', ':')


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
            ec_msg = str(exit_code)
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


class OceanStorOperationError(PosixOperationError):
    pass


class OceanStorOperations(with_metaclass(Singleton, PosixOperations)):
    def __init__(self, url, username=None, password=None):
        """Initialize REST client and request authentication token"""
        super(OceanStorOperations, self).__init__()

        self.log = fancylogger.getLogger()

        self.oceanstor_storagepools = None
        self.oceanstor_filesystems = None
        self.oceanstor_filesets = None


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

    @staticmethod
    def json_separators(): 
        """JSON formatting for OceanStor API"""
        return OCEANSTOR_JSON_SEP

    def list_storage_pools(self, update=False):
        """
        List all storage pools (equivalent to devices in GPFS)

        Set self.oceanstor_storagepools to a convenient dict structure of the returned dict
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
        if not update and self.oceanstor_storagepools:
            return self.oceanstor_storagepools

        # Request storage pools
        _, response = self.session.data_service.storagepool.get()

        # Organize in a dict by storage pool name
        storage_pools = dict()
        for sp in response['storagePools']:
            storage_pools.update({sp['storagePoolName']: sp})

        if len(storage_pools) == 0:
            self.log.raiseException("No storage pools found in OceanStor", OceanStorOperationError)
        else:
            self.log.debug("Storage pools in OceanStor: %s", ', '.join(storage_pools))

        self.oceanstor_storagepools = storage_pools
        return storage_pools

    def select_storage_pools(self, sp_names, byid=False):
        """
        Return list of existing storage pools with the provided storage pool names

        @type sp_names: list of names (if string: 1 device)
        """
        storage_pools = self.list_storage_pools()

        if not isinstance(sp_names, list):
            target_storage_pools = [sp_names]
        else:
            target_storage_pools = sp_names

        try:
            sp_select = [storage_pools[sp]['storagePoolName'] for sp in target_storage_pools]
        except KeyError as err:
            sp_miss = err.args[0]
            sp_avail = ", ".join(storage_pools)
            errmsg = "Storage pool '%s' not found in OceanStor. Use any of: %s" % (sp_miss, sp_avail)
            self.log.raiseException(errmsg, KeyError)

        # Convert names to IDs
        if byid:
            sp_select = [storage_pools[sp]['storagePoolId'] for sp in sp_select]

        return sp_select

    def list_filesystems(self, device=None, update=False):
        """
        List all filesystems

        @type device: list of names (if string: 1 device, if None or all: all known devices)

        Set self.oceanstor_filesystems to a convenient dict structure of the returned dict
        where the key is the filesystem name, the value is a dict with keys:
        - atime_update_mode
        - dentry_table_type
        - dir_split_bitwidth
        - dir_split_policy
        - id
        - is_show_snap_dir
        - name
        - qos_policy_id
        - rdc
        - record_id
        - root_split_bitwidth
        - running_status
        - storage_pool_id
        """

        # Filter by requested devices (storage pools in OceanStor)
        # Support special case 'all' for downstream compatibility
        if device is None or device == 'all':
            storage_pools = self.list_storage_pools(update=update)
            device = list(storage_pools.keys())

        sp_ids = self.select_storage_pools(device, byid=True)
        filter_sp_ids = [{'storage_pool_id': str(sp_id)} for sp_id in sp_ids]
        filter_sp_ids_json = json.dumps(filter_sp_ids, separators=self.json_separators())
        self.log.debug("Filtering filesystems in storage pools with IDs: %s", ', '.join(str(i) for i in sp_ids))

        if not update and self.oceanstor_filesystems:
            # Use cached filesystem data
            filesystems = {fs['name']: fs for fs in self.oceanstor_filesystems.values() if fs['storage_pool_id'] in sp_ids}
            dbg_prefix = "(cached) "
        else:
            # Request filesystem data
            _, response = self.session.file_service.file_systems.get(filter=filter_sp_ids_json)
            filesystems = {fs['name']: fs for fs in response['data']}
            dbg_prefix = ""

            self.oceanstor_filesystems = filesystems

        self.log.debug(dbg_prefix + "Filesystems in OceanStor: %s", ", ".join(filesystems))

        return filesystems

    def select_filesystems(self, filesystemnames, devices=None, byid=False):
        """
        Return list of existing filesytem with the provided filesystem names
        Restrict list to filesystems found in given storage pools names

        @type filesystemnames: list of filesystem names (if string: 1 filesystem)
        @type devices: list of storage pools names (if string: 1 storage pool; if None: all known storage pools)
        @type byid: boolean (if True: return list of filesystem IDs)
        """

        if not isinstance(filesystemnames, list):
            target_filesystems = [filesystemnames]
        else:
            target_filesystems = filesystemnames

        # Filter by storage pools
        filesystems = self.list_filesystems(device=devices)

        try:
            fs_select = [filesystems[fs]['name'] for fs in target_filesystems]
        except KeyError as err:
            fs_miss = err.args[0]
            fs_avail = ", ".join(filesystems)
            errmsg = "Filesystem '%s' not found in OceanStor. Use any of: %s" % (fs_miss, fs_avail)
            self.log.raiseException(errmsg, KeyError)

        # Convert names to IDs
        if byid:
            fs_select = [filesystems[fs]['id'] for fs in fs_select]

        return fs_select

    def list_filesets(self, devices=None, filesystemnames=None, filesetnames=None, update=False):
        """
        Get all dtree filesets in given devices and given filesystems
        Filter reported results by name of filesystem
        Store unfiltered data in self.fileset (all filesets in given devices and given filesystems)

        @type devices: list of devices (if string: 1 device; if None: all found devices)
        @type filesystemnames: list of filesystem names (if string: 1 filesystem; if None: all known filesystems)
        @type filesetnames: list of fileset names (if string: 1 fileset)

        Set self.oceanstor_filesets as dict with
        : keys per parent filesystemName and value is dict with
        :: keys per dtree fileset ID and value is dict with
        ::: keys returned by OceanStor:
        - group
        - id
        - name
        - owner
        - security_style
        - unix_mode
        """

        # Filter by filesystem name (in target storage pools)
        if filesystemnames is None:
            filesystems = self.list_filesystems(update=update)
            filesystemnames = list(filesystems.keys())

        filter_fs = self.select_filesystems(filesystemnames, devices)
        self.log.debug("Seeking dtree filesets in filesystems: %s", ', '.join(filter_fs))

        # Filter by fileset name
        if filesetnames is not None:
            if isinstance(filesetnames, str):
                filesetnames = [filesetnames]

            self.log.debug("Filtering dtree filesets by name: %s", ', '.join(filesetnames))

        if not update and self.oceanstor_filesets:
            # Use cached dtree fileset data and filter by filesystem name
            dbg_prefix = "(cached) "
            dtree_filesets = {fs: self.oceanstor_filesets[fs] for fs in filter_fs}
        else:
            # Request dtree filesets
            dbg_prefix = ""
            dtree_filesets = dict()
            for fs_name in filter_fs:
                # query dtrees in this filesystem
                _, response = self.session.file_service.dtrees.get(file_system_name=fs_name)
                fs_dtree = {dt['id']: dt for dt in response['data']}
                # organize dtree filesets by filesystem name
                dtree_filesets[fs_name] = fs_dtree

            # Store all dtree filesets in the selected filesystems
            self.oceanstor_filesets = dtree_filesets

        if filesetnames:
            # Filter by name of fileset
            # REST API does not accept multiple names in the filter of 'file_service/dtrees'
            # Therefore, we request all entries and filter a posteriori
            for fs in dtree_filesets:
                dtree_filesets[fs] = {
                    dt: dtree_filesets[fs][dt]
                    for dt in dtree_filesets[fs]
                    if dtree_filesets[fs][dt]['name'] in filesetnames
                }

        for fs in dtree_filesets:
            dt_names = [dtree_filesets[fs][dt]['name'] for dt in dtree_filesets[fs]]
            self.log.debug(dbg_prefix + "Dtree filesets in OceanStor filesystem '%s': %s", fs, ', '.join(dt_names))

        return dtree_filesets
