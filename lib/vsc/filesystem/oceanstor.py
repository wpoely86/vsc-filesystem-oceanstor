#
# Copyright 2022-2022 Vrije Universiteit Brussel
#
# This file is part of vsc-filesystem-oceanstor,
# originally created by the HPC team of Vrije Universiteit Brussel (https://hpc.vub.be),
# with support of Vrije Universiteit Brussel (https://www.vub.be),
# the Flemish Supercomputer Centre (VSC) (https://www.vscentrum.be),
# the Flemish Research Foundation (FWO) (http://www.fwo.be/en)
# and the Department of Economy, Science and Innovation (EWI) (http://www.ewi-vlaanderen.be/en).
#
# https://github.com/vub-hpc/vsc-filesystem-oceanstor
#
# vsc-filesystem-oceanstor is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation v2.
#
# vsc-filesystem-oceanstor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with vsc-filesystem-oceanstor.  If not, see <http://www.gnu.org/licenses/>.
#
"""
Interface for Huawei Pacific OceanStor

@author: Alex Domingo (Vrije Universiteit Brussel)
"""

from __future__ import print_function
from future.utils import with_metaclass

import json
import os
import re
import ssl
import time

from collections import namedtuple
from enum import Enum

from ipaddress import IPv4Address, AddressValueError
from socket import gethostbyname

from vsc.config.base import VSC
from vsc.filesystem.posix import PosixOperations, PosixOperationError
from vsc.utils import fancylogger
from vsc.utils.patterns import Singleton
from vsc.utils.rest import Client, RestClient
from vsc.utils.py2vs3 import HTTPError, HTTPSHandler, build_opener, is_py2


OCEANSTOR_API_PATH = ["api", "v2"]

# REST API cannot handle white spaces between keys and values
OCEANSTOR_JSON_SEP = (",", ":")

# Quota type equivalents in OceanStor
class QuotaType(Enum):
    fileset = 1
    user = 2
    group = 3


class Typ2Param(Enum):
    FILESET = 'fileset'
    USR = 'user'
    GRP = 'group'


OCEANSTOR_QUOTA_PARENT_TYPE = {
    "filesystem": 40,
    "dtree": 16445,
}

OCEANSTOR_QUOTA_UNIT_TYPE = {
    "B": 0,
    "KB": 1,
    "MB": 2,
    "GB": 3,
}

OCEANSTOR_QUOTA_USER_TYPE = {
    "local_unix_user": 1,
    "local_unix_group": 2,
    "domain_user": 3,
    "domain_group": 4,
}

OCEANSTOR_QUOTA_DOMAIN_TYPE = {
    "AD": 1,
    "LDAP": 2,
    "NIS": 3,
}

# Soft quota to hard quota factor
OCEANSTOR_QUOTA_FACTOR = 1.05

# NFS lookup cache lifetime in seconds
NFS_LOOKUP_CACHE_TIME = 60

# Keyword identifying the VSC network zone
VSC_NETWORK_LABEL = "VSC"

# Quota settings
StorageQuota = namedtuple(
    'StorageQuota',
    [
        'id',
        'name',
        'quota',
        'filesetname',
        'blockUsage',
        'blockQuota',
        'blockLimit',
        'blockInDoubt',
        'blockGrace',
        'filesUsage',
        'filesQuota',
        'filesLimit',
        'filesInDoubt',
        'filesGrace',
        'ownerName',
        'ownerType',
        'parentId',
        'parentType',
    ],
)


class OceanStorClient(Client):
    """Client for OceanStor REST API"""

    def __init__(self, *args, **kwargs):
        """Wrapper for Client.__init__() allowing to disable SSL certificate verification"""
        super(OceanStorClient, self).__init__(*args, **kwargs)

        # X-Auth-Token header
        self.x_auth_header = None
        ssl_verify = kwargs.get('ssl_verify', True)

        if ssl_verify is False:
            # Disable verification of SSL certificates
            nossl_context = ssl._create_unverified_context()
            nosslHandler = HTTPSHandler(context=nossl_context)
            self.opener = build_opener(nosslHandler)
            fancylogger.getLogger().warning("Verification of SSL certificates disabled by request!")

    def get(self, url, pagination=False, headers=None, **params):  # pylint: disable=arguments-differ
        """
        HTTP GET request of all pages in the given url with given headers and parameters
        Parameters is a dictionary that will be urlencoded
        Paginated requests append range offset and limit to given parameters

        @type pagination: bool to enable paginated queries
        """
        # GET query without pagination
        if pagination is False:
            return super(OceanStorClient, self).get(url, headers=headers, **params)

        # GET query with pagination
        query_range = {
            "offset": 0,
            "limit": 100,  # 100 is the maximum
        }

        status = None
        response = {"data": list(), "result": dict()}
        page_items = query_range["limit"]

        while page_items == query_range["limit"]:
            # loop over pages
            params["range"] = json.dumps(query_range, separators=OCEANSTOR_JSON_SEP)
            item_status, item_response = super(OceanStorClient, self).get(url, headers=headers, **params)

            # append page
            status = item_status
            response["result"] = item_response["result"]  # only keep last result
            response["data"].extend(item_response["data"])  # append data

            # update item count and jump to next page
            page_items = len(item_response["data"])
            query_range["offset"] += page_items
            fancylogger.getLogger().debug("Items in response of paginated GET query: %s", page_items)

        return status, response

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
            result = response["result"]
        except (KeyError, TypeError) as err:
            errmsg = "OceanStor response lacks resulting status: %s" % response
            fancylogger.getLogger().raiseException(errmsg, exception=err.__class__)

        try:
            exit_code = result["code"]
        except TypeError as err:
            # Some queries generate a response with an int result
            # e.g. GET 'data_service/storagepool'
            exit_code = result
            ec_msg = str(exit_code)
        else:
            ec_msg_desc = result["description"]
            if "suggestion" in result:
                ec_msg_desc += " " + result["suggestion"]
            ec_msg = "%s (%s)" % (result["code"], ec_msg_desc)

        ec_full_msg = "OceanStor query returned exit code: %s" % ec_msg
        if exit_code != 0:
            fancylogger.getLogger().raiseException(ec_full_msg, exception=RuntimeError)
        else:
            fancylogger.getLogger().debug(ec_full_msg)

        return status, response

    def get_x_auth_token(self, username, password):
        """Request authetication token"""
        query_url = os.path.join("aa", "sessions")

        payload = {
            "user_name": username,
            "password": password,
        }

        status, response = self.post(query_url, body=payload)
        fancylogger.getLogger().debug("Request for X-Auth-Token got reponse status: %s", status)

        try:
            token = response["data"]["x_auth_token"]
        except AttributeError:
            errmsg = "X-Auth-Token not found in response from OceanStor"
            fancylogger.getLogger().raiseException(errmsg, exception=AttributeError)
        else:
            self.username = username
            self.x_auth_header = {"X-Auth-Token": token}
            fancylogger.getLogger().info("OceanStor authentication switched to X-Auth-Token for this session")

        return True


class OceanStorRestClient(RestClient):
    def __init__(self, *args, **kwargs):
        """Create client for OceanStor with given arguments"""
        self.client = OceanStorClient(*args, **kwargs)


class OceanStorOperationError(PosixOperationError):
    pass


class OceanStorOperations(with_metaclass(Singleton, PosixOperations)):
    def __init__(self, url, account, username, password):
        """
        Initialize REST client and request authentication token

        @type url: string with URL of REST API, only scheme and FQDM of server is needed
        @type account: string with name of account in OceanStor
        @type username: string with username for the REST API
        @type password: string with plain password for the REST API
        """
        super(OceanStorOperations, self).__init__()

        self.dry_run = False

        self.supportedfilesystems = ["nfs", "nfs4"]
        self.ignorerealpathmismatch = True  # allow working through symlinks

        self.oceanstor_storagepools = dict()
        self.oceanstor_filesystems = dict()
        self.oceanstor_filesets = dict()

        self.oceanstor_quotas = dict()
        self.quota_types = Typ2Param

        self.oceanstor_nfsshares = dict()
        self.oceanstor_nfsclients = dict()
        self.oceanstor_nfsservers = dict()

        self.account = account

        # OceanStor API URL
        self.api_url = os.path.join(url, *OCEANSTOR_API_PATH)
        self.log.info("URL of OceanStor REST API server: %s", self.api_url)

        # Initialize REST client without user/password
        self.session = OceanStorRestClient(self.api_url)
        # Get token for this session with user/password
        self.session.client.get_x_auth_token(username, password)

    def list_storage_pools(self, update=False):
        """
        List available storage pools in OceanStor

        Set self.oceanstor_storagepools as dict with
        : keys per storagePoolName and value is dict with
        :: keys returned by OceanStor:
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
        for sp in response["storagePools"]:
            storage_pools.update({sp["storagePoolName"]: sp})

        if len(storage_pools) == 0:
            self.log.raiseException("No storage pools found in OceanStor", OceanStorOperationError)
        else:
            self.log.debug("Storage pools in OceanStor: %s", ", ".join(storage_pools))

        self.oceanstor_storagepools = storage_pools
        return storage_pools

    def select_storage_pools(self, sp_names, byid=False):
        """
        Return list of existing storage pools with the provided storage pool names

        @type sp_names: list of names (if string: 1 storage pool)
        """
        storage_pools = self.list_storage_pools()

        if not isinstance(sp_names, list):
            target_storage_pools = [sp_names]
        else:
            target_storage_pools = sp_names

        try:
            sp_select = [storage_pools[sp]["storagePoolName"] for sp in target_storage_pools]
        except KeyError as err:
            sp_miss = err.args[0]
            sp_avail = ", ".join(storage_pools)
            errmsg = "Storage pool '%s' not found in OceanStor. Use any of: %s" % (sp_miss, sp_avail)
            self.log.raiseException(errmsg, KeyError)

        # Convert names to IDs
        if byid:
            sp_select = [storage_pools[sp]["storagePoolId"] for sp in sp_select]

        return sp_select

    def list_filesystems(self, device=None, pool=None, update=False):
        """
        List filesystems in OceanStor

        @type device: list of filesystem names (if string: 1 filesystem, if None or all: all known ones)
        @type pool: list of storage pools names (if string: 1 storage pool; if None or all: all known ones)

        Set self.oceanstor_filesystems as dict with
        : keys per filesystemName and value is dict with
        :: keys returned by OceanStor:
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

        # Filter by requested storage pool
        # Support special case 'all' for downstream compatibility
        if pool is None or pool == "all":
            storage_pools = self.list_storage_pools(update=update)
            pool = list(storage_pools.keys())

        filter_sp = self.select_storage_pools(pool, byid=True)
        self.log.debug("Filtering filesystems in storage pools with IDs: %s", ", ".join(str(i) for i in filter_sp))

        if not update and self.oceanstor_filesystems:
            # Use cached filesystem data
            dbg_prefix = "(cached) "
            filesystems = {
                fs["name"]: fs for fs in self.oceanstor_filesystems.values() if fs["storage_pool_id"] in filter_sp
            }
        else:
            # Request filesystem data
            dbg_prefix = ""
            filesystems = dict()
            for sp_id in filter_sp:
                filter_json = [{"storage_pool_id": str(sp_id)}]
                filter_json = json.dumps(filter_json, separators=OCEANSTOR_JSON_SEP)
                _, response = self.session.file_service.file_systems.get(filter=filter_json)
                filesystems.update({fs["name"]: fs for fs in response["data"]})

            # Update filesystems in the selected pools
            self.oceanstor_filesystems = filesystems

        # Filter by filesystem name (device in GPFS)
        # Support special case 'all' for downstream compatibility
        if device == "all":
            device = None

        if device is not None:
            if isinstance(device, str):
                device = [device]

            self.log.debug("Filtering filesystems by name: %s", ", ".join(device))

            # REST API does not accept multiple names in the filter of 'file_service/file_systems'
            # Therefore, we filter from cached data
            filesystems = {fs_name: filesystems[fs_name] for fs_name in device}

        self.log.debug("%sFilesystems in OceanStor: %s", dbg_prefix, ", ".join(filesystems))

        return filesystems

    def select_filesystems(self, filesystemnames, pool=None, byid=False):
        """
        Return dict of existing filesytem names and their IDs that match given filesystem names
        Restrict found filesystems to given storage pools names

        @type filesystemnames: list of filesystem names (if string: 1 filesystem)
        @type pool: list of storage pools names (if string: 1 storage pool; if None: all known storage pools)
        @type byid: boolean (if True: seek filesystems by ID instead of name)
        """
        if not isinstance(filesystemnames, list):
            filesystemnames = [filesystemnames]

        target_filesystems = [str(fs) for fs in filesystemnames]

        # Filter by storage pools
        filesystems = self.list_filesystems(pool=pool)

        if byid:
            # Seek filesystems by numeric ID
            try:
                target_filesystems_id = [int(fs_id) for fs_id in target_filesystems]
            except ValueError:
                errmsg = "Malformed list of filesystem IDs: %s"
                self.log.raiseException(errmsg % ", ".join([str(fs_id) for fs_id in target_filesystems]), ValueError)
            else:
                # Convert known IDs to names
                for n, fs_id in enumerate(target_filesystems_id):
                    fs_name = [fs for fs in filesystems if filesystems[fs]["id"] == fs_id]
                    if fs_name:
                        target_filesystems[n] = fs_name[0]

            self.log.debug("Converted filesystem IDs to filesystem names: %s", ", ".join(target_filesystems))

        # Seek filesystems by name
        # (perform this step even with 'byid' to identify any not found filesystem)
        try:
            fs_select = [filesystems[fs]["name"] for fs in target_filesystems]
        except KeyError as err:
            fs_miss = err.args[0]
            fs_avail = ", ".join(filesystems)
            errmsg = "Filesystem '%s' not found in OceanStor. Use any of: %s" % (fs_miss, fs_avail)
            self.log.raiseException(errmsg, KeyError)

        # Generate dict of names and IDs
        fs_select = {fs: filesystems[fs]["id"] for fs in fs_select}
        self.log.debug("Selected OceanStor filesystems: %s", ", ".join(fs_select))

        return fs_select

    def get_filesystem_info(self, filesystem):
        """
        Get all the relevant information for a given OceanStor filesystem.

        @type filesystem: string representing the name of the filesystem in OceanStor

        @returns: dictionary with the OceanStor information

        @raise OceanStorOperationError: if there is no filesystem with the given name
        """
        self.list_filesystems()
        try:
            return self.oceanstor_filesystems[filesystem]
        except KeyError:
            errmsg = "OceanStor has no information for filesystem %s" % (filesystem)
            self.log.raiseException(errmsg, OceanStorOperationError)
            return None

    def list_filesets(self, devices=None, filesetnames=None, pool=None, update=False):
        """
        Get all dtree filesets in given devices and given filesystems
        Filter reported results by name of filesystem
        Store unfiltered data in self.oceanstor_filesets (all filesets in given devices and given filesystems)

        @type devices: list of filesystem names (if string: 1 filesystem, if None: all known ones)
        @type filesetnames: list of fileset names (if string: 1 fileset, if None: all known ones)
        @type pool: list of storage pools names (if string: 1 storage pool; if None: all known ones)

        Set self.oceanstor_filesets as dict with
        : keys per parent filesystemName and value is dict with
        :: keys per dtree fileset ID and value is dict with
        ::: keys returned by OceanStor:
        - group
        - id
        - name
        - owner
        - parent_dir
        - security_style
        - unix_mode
        """

        # Filter by filesystem name (device in GPFS) in target storage pool
        if devices is None:
            filesystems = self.list_filesystems(pool=pool, update=update)
            devices = list(filesystems.keys())

        filter_fs = self.select_filesystems(devices, pool=pool)
        self.log.debug("Seeking dtree filesets in filesystems: %s", ", ".join(filter_fs))

        dtree_filesets = dict()
        for fs_name in filter_fs:
            if not update and fs_name in self.oceanstor_filesets:
                # Use cached dtree fileset data and filter by filesystem name
                dbg_prefix = "(cached) "
                dtree_filesets[fs_name] = self.oceanstor_filesets[fs_name]
            else:
                # Request dtree filesets
                dbg_prefix = ""
                # query dtrees in this filesystem
                _, response = self.session.file_service.dtrees.get(file_system_name=fs_name)
                fs_dtree = {dt["id"]: dt for dt in response["data"]}
                # query parent directory of each individual fileset by ID (fsId@dtreeId)
                for dt_id in fs_dtree:
                    dtree_api_path = os.path.join("file_service", "dtrees", dt_id)
                    _, dt_response = self.session.get(url=dtree_api_path)
                    fs_dtree[dt_id]["parent_dir"] = dt_response["data"]["parent_dir"]

                dtree_filesets[fs_name] = fs_dtree

            dt_names = [dt["name"] for dt in dtree_filesets[fs_name].values()]
            self.log.debug(
                "%sDtree filesets in OceanStor filesystem '%s': %s", dbg_prefix, fs_name, ", ".join(dt_names)
            )

        # Update dtree filesets in the selected filesystems
        self.oceanstor_filesets.update(dtree_filesets)

        # Filter by fileset name
        if filesetnames is not None:
            if isinstance(filesetnames, str):
                filesetnames = [filesetnames]

            self.log.debug("Filtering dtree filesets by name: %s", ", ".join(filesetnames))

            # REST API does not accept multiple names in the filter of 'file_service/dtrees'
            # Therefore, we filter from cached data
            for fs in dtree_filesets.keys():
                dtree_filesets[fs] = {
                    dt: dtree_filesets[fs][dt]
                    for dt in dtree_filesets[fs]
                    if dtree_filesets[fs][dt]["name"] in filesetnames
                }

        return dtree_filesets

    def get_fileset_info(self, filesystem_name, fileset_name):
        """
        Get all the relevant information for a given fileset.

        @type filesystem_name: string representing a OceanStor filesystem
        @type fileset_name: string representing a OceanStor fileset name (not the ID)

        @returns: dictionary with the fileset information or None if the fileset cannot be found

        @raise OceanStorOperationError: if there is no filesystem with the given name
        """
        self.list_filesets(devices=filesystem_name)
        try:
            filesystem_fsets = self.oceanstor_filesets[filesystem_name]
        except KeyError:
            errmsg = "OceanStor has no fileset information for filesystem %s" % filesystem_name
            self.log.raiseException(errmsg, OceanStorOperationError)

        for fset in filesystem_fsets.values():
            if fset["name"] == fileset_name:
                return fset

        return None

    def get_fileset_name(self, fileset_id, filesystem_name):
        """
        Return name of fileset

        @type fileset_id: string with fileset ID
        @type filesystem_name: string with device name
        """
        self.list_filesets(devices=filesystem_name)

        try:
            fileset_name = self.oceanstor_filesets[filesystem_name][fileset_id]['name']
        except KeyError:
            errmsg = "Fileset ID '%s' not found in OceanStor filesystem '%s'" % (fileset_id, filesystem_name)
            self.log.raiseException(errmsg, OceanStorOperationError)
        else:
            self.log.debug("Name of fileset ID '%s': %s", fileset_id, fileset_name)
            return fileset_name

    def get_quota_fileset(self, quota_id, filesystem_name):
        """
        Return ID of fileset with given quota

        @type quota_id: string with quota ID
        @type filesystem_name: string with device name
        """
        fileset_id = None

        quotas = self.list_quota(devices=filesystem_name)
        fileset_quotas = quotas[filesystem_name][Typ2Param.FILESET.value]

        if quota_id in fileset_quotas:
            quota_obj = fileset_quotas[quota_id]
            # verify that this fileset quota is attached to a dtree
            if quota_obj.parentType == OCEANSTOR_QUOTA_PARENT_TYPE["dtree"]:
                fileset_id = quota_obj.parentId

        if fileset_id is None:
            errmsg = "Fileset quota '%s' not found in OceanStor filesystem '%s'" % (quota_id, filesystem_name)
            self.log.raiseException(errmsg, OceanStorOperationError)

        self.log.debug("Quota '%s' is attached to fileset: %s", quota_id, fileset_id)

        return fileset_id

    def get_quota_owner(self, quota_id, filesystem_name):
        """
        Return UID/GID of given quota ID

        @type quota_id: string with quota ID
        @type filesystem_name: string with device name
        """
        owner_id = None

        quotas = self.list_quota(devices=filesystem_name)

        if quota_id in quotas[filesystem_name][Typ2Param.USR.value]:
            usrgrp_quota = quotas[filesystem_name][Typ2Param.USR.value][quota_id]
        elif quota_id in quotas[filesystem_name][Typ2Param.GRP.value]:
            usrgrp_quota = quotas[filesystem_name][Typ2Param.GRP.value][quota_id]
        else:
            errmsg = "User/Group quota '%s' not found in OceanStor filesystem '%s'" % (quota_id, filesystem_name)
            self.log.raiseException(errmsg, OceanStorOperationError)

        vsc = VSC()
        owner_name = usrgrp_quota.ownerName
        owner_id = vsc.user_uid_institute_map[owner_name[:3]][0] + int(owner_name[3:])
        self.log.debug("Quota '%s' is owned by: [%s] %s", quota_id, owner_id, owner_name)

        return owner_id

    def list_nfs_shares(self, filesystemnames=None, update=False):
        """
        Get all NFS shares in given filesystems
        Filter reported results by name of filesystem

        @type filesystemnames: list of filesystem names (if string: 1 filesystem; if None: all known filesystems)

        Set self.oceanstor_nfsshares as dict with
        : keys per filesystem name and value is dict with
        :: keys per NFS share ID and value is dict with
        ::: keys returned by OceanStor:
        - account_id
        - account_name
        - description
        - dtree_id
        - file_system_id
        - id
        - share_path
        """

        # Filter by filesystem name
        if filesystemnames is None:
            filesystems = self.list_filesystems(update=update)
            filesystemnames = list(filesystems.keys())

        filter_fs = self.select_filesystems(filesystemnames)
        self.log.debug("Seeking NFS shares in filesystems: %s", ", ".join(filter_fs))

        nfs_shares = dict()
        for fs_name, fs_id in filter_fs.items():
            if not update and fs_name in self.oceanstor_nfsshares:
                # Use cached data
                dbg_prefix = "(cached) "
                nfs_shares[fs_name] = self.oceanstor_nfsshares[fs_name]
            else:
                # Request NFS shares
                dbg_prefix = ""
                filter_json = [{"fs_id": str(fs_id)}]
                filter_json = json.dumps(filter_json, separators=OCEANSTOR_JSON_SEP)
                query_params = {
                    "account_name": self.account,
                    "filter": filter_json,
                }
                _, response = self.session.nas_protocol.nfs_share_list.get(**query_params)
                fs_nfs_shares = {ns["id"]: ns for ns in response["data"]}
                nfs_shares[fs_name] = fs_nfs_shares

            nfs_desc = ["'%s'" % ns["description"] for ns in nfs_shares[fs_name].values()]
            self.log.debug("%sNFS shares in OceanStor filesystem '%s': %s", dbg_prefix, fs_name, ", ".join(nfs_desc))

        # Store all NFS shares in selected filesystems
        self.oceanstor_nfsshares.update(nfs_shares)

        return nfs_shares

    def list_nfs_clients(self, nfs_share_id=None, filesystemnames=None, update=False):
        """
        Get NFS clients for all or certain NFS shares
        Filter reported results by ID of NFS shares and/or name of filesystem

        @type nfs_share_id: list of integers with IDs of NFS shares (if int: 1 NFS share; if None: all NFS shares)
        @type filesystemnames: list of filesystem names (if string: 1 filesystem; if None: all known filesystems)

        Set self.oceanstor_nfsclients as dict with
        : keys per NFS share ID and value is dict with
        :: keys returned by OceanStor:
        - access_name
        - access_value
        - account_id
        - account_name
        - all_squash
        - id
        - root_squash
        - secure
        - security_type
        - share_id
        - sync
        - type
        """

        # NFS shares in given filesystems
        nfs_shares = self.list_nfs_shares(filesystemnames=filesystemnames, update=update)
        nfs_id_pool = [nfs_shares[fs][ns]["id"] for fs in nfs_shares for ns in nfs_shares[fs]]

        # Filter by NFS share ID
        if nfs_share_id is None:
            filter_ns = nfs_id_pool
        else:
            if not isinstance(nfs_share_id, list):
                nfs_share_id = [nfs_share_id]
            filter_ns = [str(ns) for ns in nfs_share_id if str(ns) in nfs_id_pool]

        self.log.debug("Seeking NFS clients for NFS shares: %s", ", ".join(str(i) for i in filter_ns))

        nfs_clients = dict()
        for ns_id in filter_ns:
            if not update and ns_id in self.oceanstor_nfsclients:
                # Use cached data
                dbg_prefix = "(cached) "
                nfs_clients[ns_id] = self.oceanstor_nfsclients[ns_id]
            else:
                # Request NFS clients for this share
                dbg_prefix = ""
                filter_json = [{"share_id": str(ns_id)}]
                filter_json = json.dumps(filter_json, separators=OCEANSTOR_JSON_SEP)
                query_params = {
                    "account_name": self.account,
                    "filter": filter_json,
                }
                _, response = self.session.nas_protocol.nfs_share_auth_client_list.get(**query_params)
                share_client = {nc["id"]: nc for nc in response["data"]}
                nfs_clients[ns_id] = share_client

            nc_access_name = ["'%s'" % nc["access_name"] for nc in nfs_clients[ns_id].values()]
            self.log.debug(
                "%sNFS clients for OceanStor NFS share ID '%s': %s", dbg_prefix, ns_id, ", ".join(nc_access_name)
            )

        # Store all NFS shares in selected filesystems
        self.oceanstor_nfsclients.update(nfs_clients)

        return nfs_clients

    def list_nfs_servers(self, update=False):
        """
        Return list of IPs in the VSC network of all servers in the OceanStor cluster
        """
        if not update and self.oceanstor_nfsservers:
            return self.oceanstor_nfsservers

        # Request all server IPs
        _, response = self.session.eds_dns_service.ips.get()
        nfs_servers = [node["ip_address"] for node in response["data"] if VSC_NETWORK_LABEL in node["iface_name"]]
        # Strip subnet bits from IP addresses
        nfs_servers = [ip.split("/", 1)[0] for ip in nfs_servers]

        # Validate IP addresses
        comma_sep_ips = ", ".join([str(ip) for ip in nfs_servers])
        try:
            nfs_servers = [IPv4Address(ip) for ip in nfs_servers]
        except AddressValueError:
            errmsg = "Received malformed server IPs from OceanStor: %s" % comma_sep_ips
            self.log.raiseException(errmsg, OceanStorOperationError)
        else:
            self.log.debug("NFS servers in OceanStor: %s", comma_sep_ips)

        self.oceanstor_nfsservers = nfs_servers
        return nfs_servers

    def _local_filesystems(self):
        """
        Identify local NFS filesystems from OceanStor
        Set filesystem name in OceanStor as attribute of local filesystems
        """
        super(OceanStorOperations, self)._local_filesystems()

        if self.oceanstor_filesystems is None:
            self.list_filesystems()

        # Add filesystem name in OceanStor to list of attributes of local filesystems
        self.localfilesystemnaming.append("oceanstor")

        # NFS share paths and their IDs
        oceanstor_shares = self.list_nfs_shares()
        oceanstor_share_paths = {
            os.path.normpath(nfs_share[ns]["share_path"]): nfs_share[ns]["dtree_id"]
            for nfs_share in oceanstor_shares.values()
            for ns in nfs_share
        }

        for fs in self.localfilesystems:
            oceanstor_tag = None

            if fs[self.localfilesystemnaming.index("type")] in self.supportedfilesystems:
                # Possible NFS mount from OceanStor
                mount_point = fs[self.localfilesystemnaming.index("mountpoint")]
                mount_device = fs[self.localfilesystemnaming.index("device")]
                server_address, share_path = mount_device.split(":", 1)

                # Check NFS server IP
                try:
                    server_ip_str = gethostbyname(server_address)
                    if is_py2():
                        server_ip_str = server_ip_str.decode("utf-8")
                    server_ip = IPv4Address(server_ip_str)
                except AddressValueError:
                    errmsg = "Error converting address of NFS server to an IPv4: %s" % server_address
                    self.log.raiseException(errmsg, OceanStorOperationError)

                oceanstor_nfs_servers = self.list_nfs_servers()
                if any(server_ip == oceanstor_ip for oceanstor_ip in oceanstor_nfs_servers):
                    # Check share path
                    share_path = os.path.normpath(share_path)
                    if share_path in oceanstor_share_paths:
                        oceanstor_tag = oceanstor_share_paths[share_path]
                        dbgmsg = "Local NFS mount '%s' is served by OceanStor and shares object ID: %s"
                        self.log.debug(dbgmsg, mount_point, oceanstor_tag)
                    else:
                        errmsg = "NFS mount '%s' served from OceanStor '%s' shares unknown path '%s'"
                        errmsg = errmsg % (mount_point, str(server_ip), share_path)
                        self.log.raiseException(errmsg, OceanStorOperationError)

            # Add filesystem name in OceanStor to all mounts (even if None)
            fs.append(oceanstor_tag)

    def _identify_local_path(self, local_path):
        """
        Identify the filesystem/dtree ID in OceanStor of a given directory path
        Return IDs, mount point and relative path of object in OceanStor

        @type local_path: string with directory path
        """

        # Sanity checks of local path
        if not self.exists(local_path):
            errmsg = "Path '%s' does not exist in local system."
            self.log.raiseException(errmsg % local_path, OceanStorOperationError)

        if not os.path.isdir(local_path):
            errmsg = "Path '%s' is not a directory. Cannot identify OceanStor object."
            self.log.raiseException(errmsg % local_path, OceanStorOperationError)

        local_path = os.path.realpath(local_path)  # resolve symlinks

        # Identify local mounted filesystem
        local_fs = self.what_filesystem(local_path)

        # Check NFS mount source
        oceanstor_id = local_fs[self.localfilesystemnaming.index("oceanstor")]
        if oceanstor_id is None:
            errmsg = "NFS mount of '%s' is not from OceanStor" % local_path
            self.log.raiseException(errmsg, OceanStorOperationError)

        # OceanStor IDs
        oceanstor_fs_id, oceanstor_dtree_id = oceanstor_id.split("@", 1)

        # Relative path to mount root
        local_mount = local_fs[self.localfilesystemnaming.index("mountpoint")]
        local_path_relative = os.path.relpath(local_path, start=local_mount)
        if local_path_relative.startswith(".."):
            errmsg = "Local path '%s' was resolved outside mountpoint boundaries '%s'"
            self.log.raiseException(errmsg % (local_path_relative, local_mount), OceanStorOperationError)
        elif local_path_relative == ".":
            local_path_relative = ""

        oceanstor_path = "/" + local_path_relative

        dbgmsg = "Path '%s' identified in OceanStor as object ID '%s' with relative path '%s'"
        self.log.debug(dbgmsg, local_path, oceanstor_id, oceanstor_path)

        return (oceanstor_fs_id, oceanstor_dtree_id, local_mount, oceanstor_path)

    def get_fileset_local_path(self, fileset_id):
        """
        Return local path where fileset is mounted

        @type fileset_id: string with ID of dtree fileset
        """
        fileset_path = None

        self._local_filesystems()

        for mount in [fs for fs in self.localfilesystems if fs[self.localfilesystemnaming.index("oceanstor")]]:
            mount_id = mount[self.localfilesystemnaming.index("oceanstor")]
            mount_path = mount[self.localfilesystemnaming.index("mountpoint")]
            if mount_id == fileset_id:
                # fileset is directly mounted here
                fileset_path = mount_path
            else:
                # check if mounted volume contains this fileset
                filesystem_id, _ = mount_id.split("@", 1)
                try:
                    mount_filesystem = next(iter(self.select_filesystems(filesystem_id, byid=True)))
                except ValueError:
                    self.log.debug("Fileset '%s' not found in mounted fileset '%s'", fileset_id, mount_id)
                else:
                    # get filesets in this filesystem
                    mount_filesystem_fs = self.list_filesets(devices=mount_filesystem)
                    mount_filesystem_fs = mount_filesystem_fs[mount_filesystem]
                    if fileset_id in mount_filesystem_fs:
                        mount_fileset = mount_filesystem_fs[fileset_id]
                        inner_path = os.path.join(mount_fileset["parent_dir"], mount_fileset["name"])[1:]
                        fileset_path = os.path.join(mount_path, inner_path)
                    else:
                        self.log.debug("Fileset '%s' not found in mounted filesystem '%s'", fileset_id, mount_id)

        self.log.debug("Local path of fileset '%s': %s", fileset_id, fileset_path)

        return fileset_path

    def make_fileset(
        self,
        new_fileset_path,
        fileset_name=None,
        parent_fileset_name=None,
        afm=None,
        inodes_max=1048576,
        inodes_prealloc=None,
        nfs_cache=False,
    ):
        """
        Create a new fileset in a NFS mounted filesystem from OceanStor

        - All filesets in a common filesystem must have unique names (enforced by API)
        - The name of the dtree fileset and the folder where it is mounted always share the same name
        - Dtree filesets cannot be nested (parent_fileset_name is ignored)
        - Dtree filesets can be created at specific path inside the NFS mount (i.e. filesystem)

        @type new_fileset_path: string with the full path in the local system of the new fileset
        @type fileset_name: string with the name of the new fileset
                            (if not None, fileset_name is appended to new_fileset_path)
        @type inodes_max: int with initial limit of inodes for this fileset
        @type nfs_cache: bool enabling wait time to deal with NFS lookup cache
        """
        # Unsupported features
        del afm
        del inodes_prealloc
        del parent_fileset_name

        dtree_fullpath = self._sanity_check(new_fileset_path)
        dtree_name = os.path.basename(dtree_fullpath)

        if fileset_name is not None and fileset_name != dtree_name:
            # Append the fileset name to the given path
            dtree_fullpath = os.path.join(dtree_fullpath, fileset_name)
            dtree_fullpath = self._sanity_check(dtree_fullpath)
            dtree_name = fileset_name

        # Check existence of path in local filesystem
        if self.exists(dtree_fullpath):
            errmsg = "Path of new fileset in '%s' validated as '%s' but it already exists."
            self.log.raiseException(errmsg % (new_fileset_path, dtree_fullpath), OceanStorOperationError)

        dtree_parentdir = os.path.dirname(dtree_fullpath)
        if not self.exists(dtree_parentdir):
            errmsg = "Parent directory '%s' of new fileset '%s' does not exist. It will not be created automatically."
            self.log.raiseException(errmsg % (dtree_parentdir, dtree_fullpath), OceanStorOperationError)

        # Identify local mounted filesystem
        ostor_fs_id, ostor_dtree_id, _, ostor_parentdir = self._identify_local_path(dtree_parentdir)

        # Check type of OceanStor object mounted in this path
        if int(ostor_dtree_id) == 0:
            # this NFS mount contains a filesystem
            ostor_fs_name = next(iter(self.select_filesystems(ostor_fs_id, byid=True)))
            self.log.debug("NFS mount '%s' contains OceanStor filesystem '%s'", dtree_fullpath, ostor_fs_name)
        else:
            # this NFS mount contains a dtree fileset
            errmsg = "NFS mount '%s' is already a dtree fileset (%s@%s). Nested dtrees are not allowed in OceanStor."
            self.log.raiseException(errmsg % (dtree_fullpath, ostor_fs_id, ostor_dtree_id), OceanStorOperationError)

        # Send API request to create the new dtree fileset
        dbgmsg = "Sending request for new dtree fileset '%s' in OceanStor filesystem '%s' with parent directory '%s'"
        self.log.debug(dbgmsg, fileset_name, ostor_fs_name, ostor_parentdir)

        self.make_fileset_api(fileset_name, ostor_fs_name, parent_dir=ostor_parentdir)

        if nfs_cache:
            # wait for NFS lookup cache to expire to be able to access new fileset
            time.sleep(NFS_LOOKUP_CACHE_TIME)

        # Set a default user quota: 1MB for blocks soft limit and inodes_max for inodes soft limit
        # TODO: remove once OceanStor supports setting user quotas on non-empty filesets
        block_soft = 1048576  # bytes
        self.set_user_quota(block_soft, "*", obj=dtree_fullpath, inode_soft=inodes_max)

    def make_fileset_api(self, fileset_name, filesystem_name, parent_dir="/"):
        """
        Create new dtree fileset in given filesystem of OceanStor

        - All filesets in a common filesystem must have unique names (enforced by API)
        - Dtree filesets cannot be nested
        - Dtree filesets can be created at specific paths inside the filesystem

        @type fileset_name: string with the name of the new fileset
        @type filesystem_name: string with the name of an existing filesystem
        @type parent_dir: string with path of parent directory of new fileset
                          (path relative to root of filesystem)
        """
        self.list_filesets()  # make sure fileset data is present (but do not update)

        # Check filesystem presence
        if filesystem_name not in self.oceanstor_filesets:
            errmsg = "Requested filesystem '%s' for new dtree fileset '%s' not found."
            self.log.raiseException(errmsg % (filesystem_name, fileset_name), OceanStorOperationError)

        # Check if a dtree fileset with this name alreay exists
        for dt in self.oceanstor_filesets[filesystem_name].values():
            if dt["name"] == fileset_name:
                errmsg = "Found existing dtree fileset '%s' with same name as new one '%s'"
                self.log.raiseException(errmsg % (dt["name"], fileset_name), OceanStorOperationError)

        # Check if OceanStor name constrains for dtrees are met
        unallowed_name_chars = re.compile(r"[^a-zA-Z0-9._]")
        if unallowed_name_chars.search(fileset_name):
            errmsg = "Name of new dtree fileset contains invalid characters: %s"
            self.log.raiseException(errmsg % fileset_name, OceanStorOperationError)
        elif len(fileset_name) > 255:
            errmsg = "Name of new dtree fileset is too long (max. 255 characters): %s"
            self.log.raiseException(errmsg % fileset_name, OceanStorOperationError)
        else:
            self.log.debug("Validated name of new dtree fileset: %s", fileset_name)

        # Ensure absolute path for parent directory
        # TODO: create parent directory if it does not exist
        if not os.path.isabs(parent_dir):
            parent_dir = "/" + parent_dir

        # Create dtree fileset
        new_dtree_params = {
            "name": fileset_name,
            "file_system_name": filesystem_name,
            "parent_dir": parent_dir,
        }
        self.log.debug("Creating dtree with: %s", new_dtree_params)

        if self.dry_run:
            self.log.info("(dryrun) New dtree fileset creation query: %s", new_dtree_params)
        else:
            _, result = self.session.file_service.dtrees.post(body=new_dtree_params)
            self.log.info("New dtree fileset created succesfully: %s", result)

            # Rescan all filesets and force update the info
            self.list_filesets(update=True)

    @staticmethod
    def _convert_quota_attributes(quota):
        """
        Convert quota attributes from OceanStor to the common names used in StorageQuota

        Keys returned by OceanStor and their conversion:
        - domain_type: <ignored>
        - file_advisory_quota: <ignored>
        - file_hard_quota: filesLimit
        - file_soft_quota: filesQuota
        - file_used: filesUsage
        - file_used_rate: <ignored>
        - id: id
        - parent_id: parentId
        - parent_type: parentType
        - quota_type: quota
        - record_id: <ignored>
        - resuse_name: name
        - snap_modify_write_switch: <ignored>
        - snap_space_rate: <ignored>
        - snap_space_switch: <ignored>
        - soft_grace_time: blockGrace, filesGrace
        - space_advisory_quota: <ignored>
        - space_hard_quota: blockLimit
        - space_soft_quota: blockQuota
        - space_unit_type: all block quotas are converted to bytes
        - space_used: blockUsage
        - space_used_rate: <ignored>
        - usr_grp_owner_name: ownerName
        - usr_grp_type: ownerType
        - vstore_id: <ignored>
        """
        try:
            byte_conversion = 1024 ** quota["space_unit_type"]
        except KeyError as err:
            self.log.raiseException("Missing space_unit_type attribute in quota object", KeyError)

        try:
            storage_quota = {
                "id": quota["id"],
                "name": quota["resuse_name"],
                "quota": quota["quota_type"],
                "filesetname": None,
                "blockUsage": quota["space_used"] * byte_conversion,
                "blockQuota": quota["space_soft_quota"] * byte_conversion,
                "blockLimit": quota["space_hard_quota"] * byte_conversion,
                "blockInDoubt": 0,
                "blockGrace": quota["soft_grace_time"],
                "filesUsage": quota["file_used"],
                "filesQuota": quota["file_soft_quota"],
                "filesLimit": quota["file_hard_quota"],
                "filesInDoubt": 0,
                "filesGrace": quota["soft_grace_time"],
                "ownerName": quota["usr_grp_owner_name"],
                "ownerType": quota["usr_grp_type"],
                "parentId": quota["parent_id"],
                "parentType": quota["parent_type"],
            }
        except KeyError as err:
            qa_miss = err.args[0]
            qa_avail = ", ".join(quota)
            errmsg = "Quota attribute '%s' not found. List of available attributes: %s" % (qa_miss, qa_avail)
            self.log.raiseException(errmsg, KeyError)

        # Extra filesetname attribute needed by AP
        if storage_quota["parentType"] == OCEANSTOR_QUOTA_PARENT_TYPE["dtree"]:
            # set to parent fileset ID of quota
            storage_quota["filesetname"] = storage_quota["parentId"]
        else:
            # ignore quotas of filesystems
            return None

        return storage_quota

    def list_quota(self, devices=None, update=False, alluser=False):  # pylint: disable=arguments-differ
        """
        Get quota info for all filesystems for all quota types (fileset, user, group)

        @type devices: list of filesystem names (if string: 1 filesystem; if None: all known filesystems)
        @type alluser: bool to list user default quotas

        set self.oceanstor_quotas to dict with
        : keys per filesystemName and value is dict with
        :: keys per quotaType and value is dict with
        ::: keys per quotaID and value is StorageQuota named tuple
        """
        # Filter by filesystem name (devices in GPFS)
        if devices is None:
            filesystems = self.list_filesystems()
            devices = list(filesystems.keys())
        elif isinstance(devices, str):
            devices = [devices]

        filter_fs = self.select_filesystems(devices)
        self.log.debug("Seeking quotas in filesystems IDs: %s", ", ".join(filter_fs))

        # Default quotas are not cached
        if alluser:
            update = True

        # Keep regular quotas and user default quotas in separate lists
        quotas = dict()
        default_quotas = dict()
        
        for fs_name, fs_id in filter_fs.items():
            if not update and fs_name in self.oceanstor_quotas:
                # Use cached data
                dbg_prefix = "(cached) "
                quotas[fs_name] = self.oceanstor_quotas[fs_name]
            else:
                # Request quotas for this filesystem and all its filesets
                dbg_prefix = ""
                fs_quotas = {qt.name: dict() for qt in QuotaType}
                fs_default_quotas = {qt.name: dict() for qt in QuotaType}

                query_params = {
                    "parent_type": OCEANSTOR_QUOTA_PARENT_TYPE["filesystem"],
                    "parent_id": fs_id,
                }

                # quota queries are paginated
                query_params["space_unit_type"] = OCEANSTOR_QUOTA_UNIT_TYPE["B"]  # bytes
                status, response = self.session.file_service.fs_quota.get(pagination=True, **query_params)

                if status and "data" in response:
                    # add each quota to its category in current filesystem
                    for quota_obj in response["data"]:
                        quota_type = QuotaType(quota_obj["quota_type"]).name
                        quota_attributes = self._convert_quota_attributes(quota_obj)
                        if quota_attributes:
                            quota_entry = {quota_obj["id"]: StorageQuota(**quota_attributes)}
                            if quota_entry[quota_obj["id"]].ownerName == "All User":
                                # user default quota
                                fs_default_quotas[quota_type].update(quota_entry)
                            else:
                                # regular quota
                                fs_quotas[quota_type].update(quota_entry)

                default_quotas[fs_name] = fs_default_quotas
                quotas[fs_name] = fs_quotas

            quota_count = ["%s = %s" % (qt.name, len(quotas[fs_name][qt.name])) for qt in QuotaType]
            self.log.debug(
                "%sQuota types for OceanStor filesystem '%s': %s", dbg_prefix, fs_name, ", ".join(quota_count)
            )

        # Store all regular quotas in selected filesystems
        self.oceanstor_quotas.update(quotas)

        if alluser:
            return default_quotas
        else:
            return quotas

    def _get_quota(self, who, obj, typ="user"):
        """
        Get quota information of a given local object.
        Return:
        - ID of corresponding object in OceanStor (filesystem/dtree)
        - list of quota IDs attached to it

        @type who: identifier (UID/GID/None)
        @type obj: local path with quota attribute
        @type typ: string with type of quota: fileset, user or group
        """

        quota_path = self._sanity_check(obj)
        if not self.dry_run and not self.exists(quota_path):
            errmsg = "getQuota: can't get quota on non-existing path '%s'" % quota_path
            self.log.raiseException(errmsg, OceanStorOperationError)

        if typ not in [qt.name for qt in QuotaType]:
            errmsg = "getQuota: unknown quota type '%s'" % typ
            self.log.raiseException(errmsg, OceanStorOperationError)

        # Identify OceanStor object in path
        ostor_fs_id, ostor_dtree_id, ostor_mount, ostor_path = self._identify_local_path(quota_path)
        ostor_fs_name = next(iter(self.select_filesystems(ostor_fs_id, byid=True)))

        if ostor_path == "/":
            # Target path is already an NFS mount
            if int(ostor_dtree_id) == 0:
                # mount point is a filesystem
                parent_id = ostor_fs_id
            else:
                # mount point is a dtree fileset
                parent_id = "%s@%s" % (ostor_fs_id, ostor_dtree_id)
            self.log.debug("getQuota: quota path is root of NFS mount for OceanStor object: %s", parent_id)
        else:
            # Target path can be a fileset in a mounted filesystem
            if int(ostor_dtree_id) > 0:
                errmsg = (
                    "getQuota: quota path '%s' is in a fileset '%s', but it cannot be a fileset on its own"
                    "(OceanStor does not support nested filesets)"
                )
                self.log.raiseException(errmsg % (quota_path, ostor_mount), OceanStorOperationError)

            # Find a fileset in the filesystem with the corresponding parent directory
            fs_filesets = self.list_filesets(devices=ostor_fs_name)
            fileset_parent, fileset_name = os.path.split(ostor_path)
            fileset = [
                fs["id"]
                for fs in fs_filesets[ostor_fs_name].values()
                if fs["name"] == fileset_name and fs["parent_dir"] == fileset_parent
            ]

            if len(fileset) == 1:
                parent_id = fileset[0]
                dbgmsg = "getQuota: quota path '%s' is fileset '%s' in OceanStor filesystem '%s'"
                self.log.debug(dbgmsg, quota_path, parent_id, ostor_mount)
            elif len(fileset) > 1:
                errmsg = "getQuota: found multiple filesets mathing quota path '%s' in OceanStor filesystem '%s': %s"
                self.log.raiseException(errmsg % (quota_path, ostor_mount, ",".join(fileset)), OceanStorOperationError)
            else:
                errmsg = "getQuota: could not find any fileset matching quota path '%s' in OceanStor filesystem '%s'"
                self.log.raiseException(errmsg % (quota_path, ostor_mount), OceanStorOperationError)

        # Find quotas attached to parent object
        fs_quotas = self.list_quota(devices=ostor_fs_name)
        typ_quotas = fs_quotas[ostor_fs_name][typ]
        attached_quotas = {fq.id: fq for fq in typ_quotas.values() if fq.parentId == parent_id}

        dbgmsg = "getQuota: quotas attached to parent ID '%s': %s"
        self.log.debug(dbgmsg, parent_id, ", ".join(attached_quotas))

        # Filter user/group quotas by given uid/gid
        if typ in ["user", "group"] and who is not None:
            if who == '*':
                # default quotas are not cached, query them
                default_quotas = self.list_quota(devices=ostor_fs_name, alluser=True)
                default_typ_quotas = default_quotas[ostor_fs_name][typ]
                attached_quotas = {fq.id: fq for fq in default_typ_quotas.values() if fq.parentId == parent_id}
            else:
                # select quotas this user/group
                attached_quotas = {fq.id: fq for fq in attached_quotas.values() if fq.ownerName == str(who)}
                dbgmsg = "getQuota: quotas attached to parent ID '%s' for user/group '%s': %s"
                self.log.debug(dbgmsg, parent_id, who, ", ".join(attached_quotas))

        return parent_id, tuple(attached_quotas.keys())

    def set_user_quota(self, soft, user, obj=None, hard=None, inode_soft=None, inode_hard=None):
        """
        Set quota for a user on a given object (i.e. local path)

        @type soft: integer with soft limit in bytes
        @type user: string identifying the user
        @type obj: string with local path
        @type hard: integer with hard limit in bytes. If None, OCEANSTOR_QUOTA_FACTOR * soft.
        @type inode_soft: integer with soft limit on files.
        @type inode_soft: integer with hard limit on files. If None, OCEANSTOR_QUOTA_FACTOR * inode_soft.
        """
        quota_limits = {"soft": soft, "hard": hard, "inode_soft": inode_soft, "inode_hard": inode_hard}
        self._set_quota(who=user, obj=obj, typ="user", **quota_limits)

    def set_group_quota(self, soft, group, obj=None, hard=None, inode_soft=None, inode_hard=None):
        """
        Set quota for a group on a given object (i.e. local path)

        @type soft: integer with soft limit in bytes
        @type group: string identifying the group
        @type obj: string with local path
        @type hard: integer with hard limit in bytes. If None, OCEANSTOR_QUOTA_FACTOR * soft.
        @type inode_soft: integer with soft limit on files.
        @type inode_soft: integer with hard limit on files. If None, OCEANSTOR_QUOTA_FACTOR * inode_soft.
        """
        quota_limits = {"soft": soft, "hard": hard, "inode_soft": inode_soft, "inode_hard": inode_hard}
        self._set_quota(who=group, obj=obj, typ="group", **quota_limits)

    def set_fileset_quota(self, soft, fileset_path, fileset_name=None, hard=None, inode_soft=None, inode_hard=None):
        """
        Set directory quota on filesets or filesystems.

        @type soft: integer with soft limit in bytes
        @type fileset_path: the local path to the fileset or filesystem
        @type fileset_name: IGNORED (fileset_name is determined from fileset_path)
        @type hard: integer with hard limit in bytes. If None, OCEANSTOR_QUOTA_FACTOR * soft.
        @type inode_soft: integer with soft limit on files.
        @type inode_soft: integer with hard limit on files. If None, OCEANSTOR_QUOTA_FACTOR * inode_soft.
        """

        fileset_path = self._sanity_check(fileset_path)
        if fileset_name is not None:
            infomsg = "Fileset name '%s' will be ignored. Setting fileset quota based on path: %s"
            self.log.info(infomsg, fileset_name, fileset_path)
            fileset_name = None

        quota_limits = {"soft": soft, "hard": hard, "inode_soft": inode_soft, "inode_hard": inode_hard}
        self._set_quota(who=fileset_name, obj=fileset_path, typ="fileset", **quota_limits)

        # TODO: remove once OceanStor supports creating user quotas on non-empty filesets
        # User quotas in VOs are temporarily frozen to 100% of VO fileset quota
        if "brussel/vo" in fileset_path:
            # Update default user quota in this VO to 100% of fileset quota
            self._set_quota(who="*", obj=fileset_path, typ="user", **quota_limits)

    def _set_quota(self, who, obj, typ="user", **kwargs):
        """
        Set quota on a given local object.

        @type who: identifier (username for user quota, group name for group quota, ignored for fileset quota)
        @type obj: local path
        @type typ: string with type of quota: fileset, user or group
        """

        quota_path = self._sanity_check(obj)
        if not self.dry_run and not self.exists(quota_path):
            errmsg = "setQuota: can't set quota on non-existing path '%s'" % quota_path
            self.log.raiseException(errmsg, OceanStorOperationError)

        if typ not in [qt.name for qt in QuotaType]:
            errmsg = "setQuota: unknown quota type '%s'" % typ
            self.log.raiseException(errmsg, OceanStorOperationError)

        # Check existing quotas on local object
        quota_parent, quotas = self._get_quota(who, obj, typ)

        if quotas:
            # local path already has quotas of given type
            for quota_id in quotas:
                self.log.debug("Sending request to update %s quota with ID: %s", typ, quota_id)
                self._change_quota_api(quota_id, **kwargs)
        else:
            # create new quota of given type
            self.log.debug("Sending request to create new %s quota for object ID: %s", typ, quota_parent)
            self._new_quota_api(quota_parent, typ=typ, who=who, **kwargs)

        # Update quota list from this filesystem
        ostor_fs_id = quota_parent.split("@", 1)[0]
        ostor_fs_name = next(iter(self.select_filesystems(ostor_fs_id, byid=True)))
        self.list_quota(devices=ostor_fs_name, update=True)

    def _change_quota_api(self, quota_id, **kwargs):
        """
        Modify existing quota in OceanStor

        @type quota_id: ID of existing quota
        """
        query_params = self._parse_quota_limits(**kwargs)

        # Modify existing quota
        query_params["id"] = quota_id
        if self.dry_run:
            self.log.info("(dryrun) Quota '%s' update query: %s", quota_id, query_params)
        else:
            self.session.file_service.fs_quota.put(body=query_params)
            self.log.info("Quota '%s' updated succesfully", quota_id)

    def _new_quota_api(self, quota_parent, typ="user", who=None, **kwargs):
        """
        Create new quota of given object in OceanStor

        @type quota_parent: ID of parent object holding the quota
        @type typ: string with type of quota: fileset, user or group
        @type who: identifier (username for user quota, group name for group quota, ignored for fileset quota)
        """
        query_params = self._parse_quota_limits(**kwargs)

        # Type of parent object
        id_type = len([c for c in quota_parent if c == "@"])
        parent_type = "filesystem" if id_type == 0 else "dtree"
        self.log.debug("Quota parent object '%s' determined to be '%s'", quota_parent, parent_type)

        # Create new quota
        query_params["parent_id"] = quota_parent
        query_params["parent_type"] = OCEANSTOR_QUOTA_PARENT_TYPE[parent_type]
        query_params["quota_type"] = QuotaType[typ].value

        if typ in ["user", "group"]:
            # settings for user/group quotas
            if who is None:
                errmsg = "Cannot ser user/group quota on '%s', account information missing."
                self.log.raiseException(errmsg % quota_parent, OceanStorOperationError)

            query_params["usr_grp_owner_name"] = str(who)

            if who == "*":
                # special case: all users
                query_params["usr_grp_type"] = 1
            else:
                # LDAP user/group
                usr_grp_type = "domain_%s" % typ
                query_params["usr_grp_type"] = OCEANSTOR_QUOTA_USER_TYPE[usr_grp_type]
                query_params["domain_type"] = OCEANSTOR_QUOTA_DOMAIN_TYPE["LDAP"]

        elif parent_type == "filesystem":
            # directory quotas target dtrees (0) by default, switch to filesystems (1)
            query_params["directory_quota_target"] = 1

        if self.dry_run:
            self.log.info("(dryrun) New quota creation query: %s", query_params)
        else:
            _, response = self.session.file_service.fs_quota.post(body=query_params)
            new_quota_id = response["data"]["id"]
            self.log.info("Quota '%s' created succesfully", new_quota_id)

    def _parse_quota_limits(self, soft=None, hard=None, inode_soft=None, inode_hard=None):
        """
        Parse quota limits and generate corresponding query parameters

        @type soft: integer with soft limit in bytes.
        @type hard: integer with hard limit in bytes. If None, OCEANSTOR_QUOTA_FACTOR * soft.
        @type inode_soft: integer with soft limit on files.
        @type inode_soft: integer with hard limit on files. If None, OCEANSTOR_QUOTA_FACTOR * inode_soft.
        """

        if soft is None and inode_soft is None:
            errmsg = "setQuota: At least one type of quota (block or inode) should be specified"
            self.log.raiseException(errmsg, OceanStorOperationError)

        query_params = {"space_unit_type": OCEANSTOR_QUOTA_UNIT_TYPE["B"]}  # bytes

        if soft:
            # Set space quota
            if hard is None:
                hard = int(soft * OCEANSTOR_QUOTA_FACTOR)
            elif hard < soft:
                errmsg = "setQuota: can't set a hard limit %s lower than soft limit %s"
                self.log.raiseException(errmsg % (hard, soft), OceanStorOperationError)

            # Space quota limits
            query_params["space_soft_quota"] = soft
            query_params["space_hard_quota"] = hard

        if inode_soft:
            # Set inodes quota
            if inode_hard is None:
                inode_hard = int(inode_soft * OCEANSTOR_QUOTA_FACTOR)
            elif inode_hard < inode_soft:
                errmsg = "setQuota: can't set hard inode limit %s lower than soft inode limit %s"
                self.log.raiseException(errmsg % (inode_hard, inode_soft), OceanStorOperationError)

            # Inodes quota limits
            query_params["file_soft_quota"] = inode_soft
            query_params["file_hard_quota"] = inode_hard

        return query_params

    def set_user_grace(self, obj, grace=0):
        """
        Set the grace period for user quota.

        @type obj: string with local path
        @type grace: grace period in seconds
        """
        self._set_grace(obj, "user", grace)

    def set_group_grace(self, obj, grace=0):
        """
        Set the grace period for group quota.

        @type obj: string with local path
        @type grace: grace period in seconds
        """
        self._set_grace(obj, "group", grace)

    def set_fileset_grace(self, obj, grace=0):
        """
        Set the grace period for directory quota.

        @type obj: string with local path
        @type grace: grace period in seconds
        """
        self._set_grace(obj, "fileset", grace)

    def _set_grace(self, obj, typ, grace=0):
        """Set the grace period for a given type of objects

        @type obj: the path
        @type typ: string with type of quota: fileset, user or group
        @type grace: int with grace period in seconds
        """

        quota_path = self._sanity_check(obj)
        if not self.dry_run and not self.exists(quota_path):
            errmsg = "setGrace: can't set grace on non-existing path '%s'" % quota_path
            self.log.raiseException(errmsg, OceanStorOperationError)

        if typ not in [qt.name for qt in QuotaType]:
            errmsg = "setGrace: unknown quota type '%s'" % typ
            self.log.raiseException(errmsg, OceanStorOperationError)

        # Find all existing quotas attached to local object
        quota_parent, quotas = self._get_quota(None, obj, typ)

        if not quotas:
            errmsg = "setGrace: %s quota of '%s' not found" % (typ, quota_path)
            self.log.raiseException(errmsg, OceanStorOperationError)

        # Set grace period
        grace_days = int(round(grace / (24 * 3600)))
        for quota_id in quotas:
            self.log.debug("Sending request to set grace of quota with ID: %s", quota_id)
            self._set_grace_api(quota_id, grace_days)

        # Update quota list from this filesystem
        ostor_fs_id = quota_parent.split("@", 1)[0]
        ostor_fs_name = next(iter(self.select_filesystems(ostor_fs_id, byid=True)))
        self.list_quota(devices=ostor_fs_name, update=True)

    def _set_grace_api(self, quota_id, grace):
        """
        Set grace period in existing quota in OceanStor

        @type quota_id: ID of existing quota
        @type grace: int with grace period in days
        """
        # Modify existing quota
        query_params = {
            "id": quota_id,
            "soft_grace_time": grace,
        }

        if self.dry_run:
            self.log.info("(dryrun) Grace period of quota '%s' update query: %s", quota_id, query_params)
        else:
            self.session.file_service.fs_quota.put(body=query_params)
            self.log.info("Grace period of quota '%s' updated succesfully: %s days", quota_id, grace)

    @staticmethod
    def determine_grace_periods(quota):
        """
        Determine if grace period has expired

        @type quota: StorageQuota named tuple

        @returns: grace expiration on blocks and grace expiration on files
        """

        block_expire = OceanStorOperations._get_grace_expiration(
            quota.blockGrace, quota.blockUsage, quota.blockQuota, quota.blockLimit
        )
        files_expire = OceanStorOperations._get_grace_expiration(
            quota.filesGrace, quota.filesUsage, quota.filesQuota, quota.filesLimit
        )

        return block_expire, files_expire

    @staticmethod
    def _get_grace_expiration(grace, usage, soft, hard):
        """
        Figure out if grace period has expired from the usage and quota limits
        OceanStor API does not provide the remaining 'soft_grace_time' in overquota

        @type grace: grace period in days
        @type usage: data usage in bytes
        @type soft: soft quota limit in bytes
        @type hard: hard quota limit in bytes

        @returns tuple: (expiration state, grace time)
        """
        if grace == 0:
            # unlimited grace time: set very long grace time
            grace = 9999
            fancylogger.getLogger().debug("Effective period of unlimited grace time set to %s days", grace)

        if usage > soft:
            # over quota
            if soft < hard:
                # grace not expired: we only know the maximum grace time
                grace_time = grace * 24 * 3600
            else:
                # grace expired
                grace_time = 0
            expired = (True, grace_time)
        else:
            # below soft quota
            expired = (False, None)

        return expired
