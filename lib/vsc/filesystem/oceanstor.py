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

    def storage_pool_names_to_ids(self, sp_names):
        """
        Returns list of existing IDs for the provided storage pools names

        @type sp_names: list of devices (if string: 1 device; if None or all: all known devices)
        """
        storage_pools = self.list_storage_pools()

        if sp_names == 'all' or sp_names is None:
            target_storage_pools = storage_pools.keys()
        elif not isinstance(sp_names, list):
            target_storage_pools = [sp_names]
        else:
            target_storage_pools = sp_names

        try:
            sp_ids = [str(storage_pools[sp]['storagePoolId']) for sp in target_storage_pools]
        except KeyError as err:
            sp_miss = err.args[0]
            sp_avail = ", ".join(storage_pools)
            errmsg = "Storage pool '%s' not found in OceanStor. Use any of: %s" % (sp_miss, sp_avail)
            self.log.raiseException(errmsg, KeyError)

        return sp_ids

    def list_filesystems(self, device='all', update=False):
        """
        List all filesystems

        Set self.filesystems to a convenient dict structure of the returned dict
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

        storage_pools = self.list_storage_pools(update=update)

        # Filter by requested devices (storage pools in OceanStor)
        sp_ids = self.storage_pool_names_to_ids(device)
        filter_sp_ids = [{'storage_pool_id': sp_id} for sp_id in sp_ids]
        filter_sp_ids_json = json.dumps(filter_sp_ids, separators=(',', ':'))
        self.log.debug("Filtering filesystems in storage pools with IDs: %s", ', '.join(sp_ids))

        if not update and self.filesystems:
            # Use cached filesystem data
            filesystems = {fs['name']: fs for fs in self.filesystems.values() if str(fs['storage_pool_id']) in sp_ids}
            dbg_prefix = "(cached) "
        else:
            # Request filesystem data
            _, response = self.session.file_service.file_systems.get(filter=filter_sp_ids_json)
            filesystems = {fs['name']: fs for fs in response['data']}
            dbg_prefix = ""

            self.filesystems = filesystems

        self.log.debug(dbg_prefix + "Filesystems in OceanStor: %s", ", ".join(filesystems))

        return filesystems

    def filesystem_names_to_ids(self, fs_names, sp_names=None):
        """
        Returns list of existing IDs for the provided filesystem names
        Restrict list to filesystems found in given storage pools names

        @type fs_names: list of filesystem names (if string: 1 filesystem; if None: all known filesystems)
        @type sp_ids: list of storage pools names (if string: 1 storage pool; if None: all known storage pools)
        """
        filesystems = self.list_filesystems()

        if fs_names is None:
            target_filesystems = filesystems
        elif not isinstance(fs_names, list):
            target_filesystems = [fs_names]
        else:
            target_filesystems = fs_names

        # Filter by storage pools
        sp_ids = self.storage_pool_names_to_ids(sp_names)

        try:
            fs_ids = [
                str(filesystems[fs]['id'])
                for fs in target_filesystems
                if str(filesystems[fs]['storage_pool_id']) in sp_ids
            ]
        except KeyError as err:
            fs_miss = err.args[0]
            fs_avail = ", ".join(filesystems)
            errmsg = "Filesystem '%s' not found in OceanStor. Use any of: %s" % (fs_miss, fs_avail)
            self.log.raiseException(errmsg, KeyError)

        return fs_ids

    def list_filesets(self, devices=None, filesystemnames=None, filesetnames=None, update=False):
        """
        Get all the filesets for one or more specific devices

        @type devices: list of devices (if string: 1 device; if None: all found devices)
        @type filesystemnames: report only on given filesystems (if string: 1 device; if None: all known filesystems)
        @type filesetnames: report only on given filesets (if string: 1 filesetname)

        Set self.filesets is dict with
        where the key is the dtree fileset id, the value is a dict with keys:
        - group
        - id
        - name
        - owner
        - security_style
        - unix_mode
        - parent_fs_id
        """

        filesystems = self.list_filesystems(update=update)

        # Filter by filesystem name (in target storage pools)
        filter_fs_ids = self.filesystem_names_to_ids(filesystemnames, devices)
        self.log.debug("Filtering dtree filesets in filesystems with IDs: %s", ', '.join(filter_fs_ids))

        # Filter by fileset name
        query_params = dict()
        if filesetnames is not None:
            if isinstance(filesetnames, str):
                filesetnames = [filesetnames]

            filter_dt_names = [{'name': dt_name} for dt_name in filesetnames]
            filter_dt_names_json = json.dumps(filter_dt_names, separators=(',', ':'))
            query_params['filter'] = filter_dt_names_json
            self.log.debug("added dtree fileset filter by name: %s", ', '.join(filter_dt_names_json))

        if not update and self.filesets:
            # Use cached dtree fileset data
            dtree_filesets = [dt for dt in self.filesets.values() if dt['parent_fs_id'] in filter_fs_ids]
            if filesetnames:
                dtree_filesets = [dt for dt in dtree_filesets if dt['name'] in filesetnames]
            dtree_filesets = {dt['id']: dt for dt in dtree_filesets}
            dbgmsg = "(cached) Dtree filesets in OceanStor filesystems: %s"
            self.log.debug(dbgmsg, ', '.join(dtree_filesets))
        else:
            # Request dtree filesets
            dtree_filesets = dict()
            for fs_id in filter_fs_ids:
                query_params['file_system_id'] = fs_id
                _, response = self.session.file_service.dtrees.get(**query_params)
                fs_dtree = {dt['id']: dt for dt in response['data']}
                self.log.debug("Dtree filesets in OceanStor filesystem ID '%s': %s", fs_id, ', '.join(fs_dtree))

                dtree_extras = {'parent_fs_id': fs_id}
                for dt in fs_dtree:
                    fs_dtree[dt].update(dtree_extras)

                dtree_filesets.update(fs_dtree)

            self.filesets = dtree_filesets

        return dtree_filesets
