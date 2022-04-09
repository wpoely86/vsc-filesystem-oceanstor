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
import re
import ssl

from ipaddress import IPv4Address, AddressValueError

from vsc.filesystem.posix import PosixOperations, PosixOperationError
from vsc.utils import fancylogger
from vsc.utils.patterns import Singleton
from vsc.utils.rest import Client, RestClient
from vsc.utils.py2vs3 import HTTPError, HTTPSHandler, build_opener

OCEANSTOR_API_PATH = ['api', 'v2']

# REST API cannot handle white spaces between keys and values
OCEANSTOR_JSON_SEP = (',', ':')

# Keyword identifying the VSC network zone
VSC_NETWORK_LABEL = 'VSC'


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

    def get_x_auth_token(self, username, password):
        """Request authetication token"""
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
            self.username = username
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
    def __init__(self, api_url, account, username, password):
        """
        Initialize REST client and request authentication token

        @type api_url: string with URL of REST API, only scheme and FQDM of server is needed
        @type account: string with name of account in OceanStor
        @type username: string with username for the REST API
        @type password: string with plain password for the REST API
        """
        super(OceanStorOperations, self).__init__()

        self.supportedfilesystems = ['nfs']

        self.oceanstor_storagepools = None
        self.oceanstor_filesystems = None
        self.oceanstor_filesets = None

        self.oceanstor_nfsshares = None
        self.oceanstor_nfsclients = None
        self.oceanstor_nfsservers = None

        self.account = account

        # OceanStor API URL
        self.api_url = os.path.join(api_url, *OCEANSTOR_API_PATH)
        self.log.info("URL of OceanStor REST API server: %s", self.api_url)

        # Initialize REST client without user/password
        self.session = OceanStorRestClient(self.api_url, ssl_verify=False)
        # Get token for this session with user/password
        self.session.client.get_x_auth_token(username, password)

    @staticmethod
    def json_separators():
        """JSON formatting for OceanStor API"""
        return OCEANSTOR_JSON_SEP

    def list_storage_pools(self, update=False):
        """
        List all storage pools (equivalent to devices in GPFS)

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

        # Filter by requested devices (storage pools in OceanStor)
        # Support special case 'all' for downstream compatibility
        if device is None or device == 'all':
            storage_pools = self.list_storage_pools(update=update)
            device = list(storage_pools.keys())

        filter_sp = self.select_storage_pools(device, byid=True)
        self.log.debug("Filtering filesystems in storage pools with IDs: %s", ', '.join(str(i) for i in filter_sp))

        if not update and self.oceanstor_filesystems:
            # Use cached filesystem data
            dbg_prefix = "(cached) "
            filesystems = {
                fs['name']: fs for fs in self.oceanstor_filesystems.values() if fs['storage_pool_id'] in filter_sp
            }
        else:
            # Request filesystem data
            dbg_prefix = ""
            filesystems = dict()
            for sp_id in filter_sp:
                filter_json = [{'storage_pool_id': str(sp_id)}]
                filter_json = json.dumps(filter_json, separators=self.json_separators())
                _, response = self.session.file_service.file_systems.get(filter=filter_json)
                filesystems.update({fs['name']: fs for fs in response['data']})

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
        Store unfiltered data in self.oceanstor_filesets (all filesets in given devices and given filesystems)

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
        if self.oceanstor_filesets is None:
            self.oceanstor_filesets = dict()

        # Filter by filesystem name (in target storage pools)
        if filesystemnames is None:
            filesystems = self.list_filesystems(update=update)
            filesystemnames = list(filesystems.keys())

        filter_fs = self.select_filesystems(filesystemnames, devices=devices)
        self.log.debug("Seeking dtree filesets in filesystems: %s", ', '.join(filter_fs))

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
                fs_dtree = {dt['id']: dt for dt in response['data']}
                dtree_filesets[fs_name] = fs_dtree

            dt_names = [dt['name'] for dt in dtree_filesets[fs_name].values()]
            self.log.debug(dbg_prefix + "Dtree filesets in OceanStor filesystem '%s': %s", fs_name, ', '.join(dt_names))

        # Update dtree filesets in the selected filesystems
        self.oceanstor_filesets.update(dtree_filesets)

        # Filter by fileset name
        if filesetnames is not None:
            if isinstance(filesetnames, str):
                filesetnames = [filesetnames]

            self.log.debug("Filtering dtree filesets by name: %s", ', '.join(filesetnames))

            # REST API does not accept multiple names in the filter of 'file_service/dtrees'
            # Therefore, we filter from cached data
            for fs in dtree_filesets:
                dtree_filesets[fs] = {
                    dt: dtree_filesets[fs][dt]
                    for dt in dtree_filesets[fs]
                    if dtree_filesets[fs][dt]['name'] in filesetnames
                }

        return dtree_filesets

    def list_nfs_shares(self, filesystemnames=None, update=False):
        """
        Get all NFS shares in given filesystems
        Filter reported results by name of filesystem

        @type filesystemnames: list of filesystem names (if string: 1 filesystem; if None: all known filesystems)

        Set self.oceanstor_nfsshares as dict with
        : keys per filesystem ID and value is dict with
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
        if self.oceanstor_nfsshares is None:
            self.oceanstor_nfsshares = dict()

        # Filter by filesystem name
        if filesystemnames is None:
            filesystems = self.list_filesystems(update=update)
            filesystemnames = list(filesystems.keys())

        filter_fs = self.select_filesystems(filesystemnames, byid=True)
        self.log.debug("Seeking NFS shares in filesystems: %s", ', '.join(str(i) for i in filter_fs))

        nfs_shares = dict()
        for fs_id in filter_fs:
            if not update and fs_id in self.oceanstor_nfsshares:
                # Use cached data
                dbg_prefix = "(cached) "
                nfs_shares[fs_id] = self.oceanstor_nfsshares[fs_id]
            else:
                # Request NFS shares
                dbg_prefix = ""
                filter_json = [{'fs_id': str(fs_id)}]
                filter_json = json.dumps(filter_json, separators=self.json_separators())
                query_params = {
                    'account_name': self.account,
                    'filter': filter_json,
                }
                _, response = self.session.nas_protocol.nfs_share_list.get(**query_params)
                fs_nfs_shares = {ns['id']: ns for ns in response['data']}
                nfs_shares[fs_id] = fs_nfs_shares

            nfs_desc = ["'%s'" % ns['description'] for ns in nfs_shares[fs_id].values()]
            dbgmsg = "NFS shares in OceanStor filesystem ID '%s': %s"
            self.log.debug(dbg_prefix + dbgmsg, fs_id, ', '.join(nfs_desc))

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
        if self.oceanstor_nfsclients is None:
            self.oceanstor_nfsclients = dict()

        # NFS shares in given filesystems
        nfs_shares = self.list_nfs_shares(filesystemnames=filesystemnames, update=update)
        nfs_id_pool = [nfs_shares[fs][ns]['id'] for fs in nfs_shares for ns in nfs_shares[fs]]

        # Filter by NFS share ID
        if nfs_share_id is None:
            filter_ns = nfs_id_pool
        else:
            if not isinstance(nfs_share_id, list):
                nfs_share_id = [nfs_share_id]
            filter_ns = [str(ns) for ns in nfs_share_id if str(ns) in nfs_id_pool]

        self.log.debug("Seeking NFS clients for NFS shares: %s", ', '.join(str(i) for i in filter_ns))

        nfs_clients = dict()
        for ns_id in filter_ns:
            if not update and ns_id in self.oceanstor_nfsclients:
                # Use cached data
                dbg_prefix = "(cached) "
                nfs_clients[ns_id] = self.oceanstor_nfsclients[ns_id]
            else:
                # Request NFS clients for this share
                dbg_prefix = ""
                filter_json = [{'share_id': str(ns_id)}]
                filter_json = json.dumps(filter_json, separators=self.json_separators())
                query_params = {
                    'account_name': self.account,
                    'filter': filter_json,
                }
                _, response = self.session.nas_protocol.nfs_share_auth_client_list.get(**query_params)
                share_client = {nc['id']: nc for nc in response['data']}
                nfs_clients[ns_id] = share_client

            nc_access_name = ["'%s'" % nc['access_name'] for nc in nfs_clients[ns_id].values()]
            dbgmsg = "NFS clients for OceanStor NFS share ID '%s': %s"
            self.log.debug(dbg_prefix + dbgmsg, ns_id, ', '.join(nc_access_name))

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
        nfs_servers = [node['ip_address'] for node in response['data'] if VSC_NETWORK_LABEL in node['iface_name']]
        # Strip subnet bits from IP addresses
        nfs_servers = [ip.split('/', 1)[0] for ip in nfs_servers]

        # Validate IP addresses
        comma_sep_ips = ', '.join([str(ip) for ip in nfs_servers])
        try:
            nfs_servers = [IPv4Address(ip) for ip in nfs_servers]
        except AddressValueError as err:
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
        self.localfilesystemnaming.append('oceanstor')

        # NFS share paths and their IDs
        oceanstor_shares = self.list_nfs_shares()
        oceanstor_share_paths = {
            os.path.normpath(nfs_share[ns]['share_path']): nfs_share[ns]['dtree_id']
            for nfs_share in oceanstor_shares.values() for ns in nfs_share
        }

        for fs in self.localfilesystems:
            oceanstor_tag = None

            if fs[self.localfilesystemnaming.index('type')] in self.supportedfilesystems:
                # Possible NFS mount from OceanStor
                mount_point = fs[self.localfilesystemnaming.index('mountpoint')]
                mount_device = fs[self.localfilesystemnaming.index('device')]
                server_ip, share_path = mount_device.split(':', 1)

                # Check NFS server IP
                server_ip = IPv4Address(server_ip)
                oceanstor_nfs_servers = self.list_nfs_servers()
                if any(server_ip == oceanstor_ip for oceanstor_ip in oceanstor_nfs_servers):
                    # Check share path
                    share_path = os.path.normpath(share_path)
                    if share_path in oceanstor_share_paths:
                        oceanstor_tag = oceanstor_share_paths[share_path]
                        dbgmsg = "Local NFS mount '%s' is served by OceanStor and shares object ID: %s"
                        self.log.debug(dbgmsg, mount_point, oceanstor_tag) 
                    else:
                        errmsg = "NFS mount '%s' served from OceanStor '%s' shares unkown path '%s'"
                        errmsg = errmsg % (mount_point, str(server_ip), share_path)
                        self.log.raiseException(errmsg, OceanStorOperationError)

            # Add filesystem name in OceanStor to all mounts (even if None)
            fs.append(oceanstor_tag)

    def make_fileset(self, new_fileset_path, fileset_name=None, parent_fileset_name=None, afm=None,
                     inodes_max=None, inodes_prealloc=None):
        """
        Create a new fileset in a NFS mounted filesystem from OceanStor

        - The name of the dtree fileset and the folder where it is mounted always share the same name.
        - Dtree filesets cannot be nested (parent_fileset_name is ignored)
        - Dtree filesets can be created at specific path inside the NFS mount (i.e. filesystem),
          but this information cannot be retrieved back from the OceanStor API (list_filesets()).
          Therefore, all filesets in a common filesystem must have unique names.

        @type new_fileset_path: string with the full path in the local system of the new fileset
        @type fileset_name: string with the name of the new fileset
                            (if not None, fileset_name is appended to new_fileset_path)
        """
        # Unsupported features
        del parent_fileset_name
        del afm
        del inodes_max
        del inodes_prealloc

        dt_fullpath = self._sanity_check(new_fileset_path)

        if fileset_name is None:
            # Use name of last folder as name of dtree fileset in OceanStor
            fileset_name = os.path.basename(dt_fullpath)
        else:
            # Append the fileset name to the given path
            dt_fullpath = os.path.join(dt_fullpath, fileset_name)
            dt_fullpath = self._sanity_check(dt_fullpath)

        # Check existence of path in local filesystem
        if self.exists(dt_fullpath):
            errmsg = "Path of new fileset '%s' is validated as '%s' but it already exists."
            self.log.raiseException(errmsg % (new_fileset_path, dt_fullpath), OceanStorOperationError)

        dt_parentdir = os.path.dirname(dt_fullpath)
        if not self.exists(dt_parentdir):
            errmsg = "Parent directory '%s' of new fileset '%s' does not exist. It will not be created automatically."
            self.log.raiseException(errmsg % (dt_parentdir, dt_fullpath), OceanStorOperationError)

        # Get local mounted filesystem and remote one in OceanStor
        local_fs = self.what_filesystem(dt_parentdir)
        local_mount = local_fs[self.localfilesystemnaming.index('mountpoint')]
        oceanstor_fs_name = local_fs[self.localfilesystemnaming.index('oceanstorfs')]

        # Relative path of parent directory holding the fileset
        dt_parentdir_relative = os.path.relpath(dt_parentdir, start=local_mount)
        if dt_parentdir_relative.startswith('..'):
            errmsg = "Parent directory of new fileset cannot be outside of filesystem boundaries. %s got: '%s'"
            self.log.raiseException(errmsg % (fileset_name, dt_parentdir_relative), OceanStorOperationError)
        elif dt_parentdir_relative == '.':
            dt_parentdir_relative = ''

        oceanstor_parentdir = '/' + dt_parentdir_relative
        self.log.debug("Creating new dtree fileset with parent directory: '%s'", oceanstor_parentdir)

        # Send API request to create the new dtree fileset
        self.make_fileset_api(fileset_name, oceanstor_fs_name, parent_dir=oceanstor_parentdir)

    def make_fileset_api(self, fileset_name, filesystem_name, parent_dir='/'):
        """
        Create new dtree fileset in given filesystem of OceanStor

        - Dtree filesets cannot be nested
        - Dtree filesets can be created at specific path inside the filesystem,
          but this information cannot be retrieved back from the OceanStor API
          (list_filesets()). Therefore, all filesets in a common filesystem must
          have unique names.

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
            if dt['name'] == fileset_name:
                errmsg = "Found existing dtree fileset '%s' with same name as new one '%s'"
                self.log.raiseException(errmsg % (dt['name'], fileset_name), OceanStorOperationError)

        # Check if OceanStor name constrains for dtrees are met
        unallowed_name_chars = re.compile(r'[^a-zA-Z0-9._]')
        if unallowed_name_chars.search(fileset_name):
            errmsg = "Name of new dtree fileset contains invalid characters: %s"
            self.log.raiseException(errmsg % fileset_name, OceanStorOperationError)
        elif len(fileset_name) > 255:
            errmsg = "Name of new dtree fileset is too long (max. 255 characters): %s"
            self.log.raiseException(errmsg % fileset_name, OceanStorOperationError)
        else:
            self.log.debug("Validated name of new dtree fileset: %s", fileset_name)

        # Ensure absolute path for parent directory
        if not os.path.isabs(parent_dir):
            parent_dir = '/' + parent_dir

        # Create dtree fileset
        new_dtree_params = {
            "name": fileset_name,
            "file_system_name": filesystem_name,
            "parent_dir": parent_dir,
        }
        self.log.debug("Creating dtree with: %s", new_dtree_params)

        _, result = self.session.file_service.dtrees.post(body=new_dtree_params)
        self.log.info("New dtree fileset created succesfully: %s", result)

        # Rescan all filesets and force update the info
        self.list_filesets(update=True)
