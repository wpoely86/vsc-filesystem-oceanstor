#
# Copyright 2022-2023 Vrije Universiteit Brussel
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
Tests for the oceanstor library.

@author: Alex Domingo (Vrije Universiteit Brussel)
"""
from __future__ import print_function

import os
import mock
import vsc.filesystem.oceanstor as oceanstor

from vsc.install.testing import TestCase

FAKE_INIT_PARAMS = ("oceanstor.url", "oceanstor_account", "oceanstor_user", "oceanstor_secret")

API_RESPONSE = {
    "account.accounts": {
        "data": [
            {
                "canonical_user_id": "00000000000000000000000000000000",
                "id": "0000000000",
                "name": "test",
                "status": "Active",
            },
        ],
        "result": {
            "code": 0,
            "description": "",
        },
    },
    "data_service.storagepool": {
        "storagePools": [
            {
                "storagePoolId": 0,
                "storagePoolName": "StoragePool0",
            },
        ],
        "result": 0,
    },
    "converged_service.namespaces": {
        "data": [
            {
                "id": 30,
                "name": "test",
                "storage_pool_id": 0,
            },
            {
                "id": 40,
                "name": "data",
                "storage_pool_id": 0,
            },
        ],
        "result": {
            "code": 0,
            "description": "",
        },
    },
    "file_service.dtrees": {
        "data": [
            {
                "group": "",
                "id": "30@4097",
                "name": "dttest",
                "owner": "",
            },
            {
                "group": "",
                "id": "30@4098",
                "name": "dttest2",
                "owner": "",
            },
            {
                "group": "",
                "id": "30@40963",
                "name": "100",
                "owner": "",
            },
        ],
        "result": {
            "code": 0,
            "description": "",
        },
    },
    "file_service.snapshots.fs": {
        "data": [
            {
                "dtree_id": "30@0",
                "dtree_name": "",
                "file_system_id": 30,
                "file_system_name": "test",
                "id": "128849018880@34585",
                "name": "SNAP_TEST_01",
            },
            {
                "dtree_id": "30@0",
                "dtree_name": "",
                "file_system_id": 30,
                "file_system_name": "test",
                "id": "128849018880@34590",
                "name": "SNAP_TEST_02",
            },
        ],
        "result": {
            "code": 0,
            "description": "",
        },
    },
    "file_service.snapshots.dtree": {
        "data": [
            {
                "dtree_id": "30@4097",
                "dtree_name": "dttest",
                "file_system_id": 30,
                "file_system_name": "test",
                "id": "128849022977@1073776411",
                "name": "dttest_SNAP_TEST_01",
            },
            {
                "dtree_id": "30@4097",
                "dtree_name": "dttest",
                "file_system_id": 30,
                "file_system_name": "test",
                "id": "128849022977@1073776413",
                "name": "dttest_SNAP_TEST_03",
            },
        ],
        "result": {
            "code": 0,
            "description": "",
        },
    },
    "file_service.snapshots.post": {
        "data": {
            "id": "128849018880@34595",
        },
        "result": {
            "code": 0,
            "description": "",
        },
    },
    "file_service.snapshots.delete": {
        "data": {},
        "result": {
            "code": 0,
            "description": "",
        },
    },
}


def api_response_get_side_effect(url=None, *args):
    """
    Mock certain GET responses from URLs with special characters
    """
    response = {"data": []}

    if "file_service/dtrees" in url:
        response["data"] = {
            "parent_dir": "/test",
        }

    return (0, response)


def api_response_dtree_side_effect(file_system_name=None, *args):
    """
    Mock GET responses of file_service/drees depending on the filesystem name
    """
    response = {"data": []}

    if file_system_name == "test":
        response = API_RESPONSE["file_service.dtrees"]

    return (0, response)


def api_response_snapshots_side_effect(filter=None, *args, **kwargs):
    """
    Mock GET responses of file_service/snapshots depending on filter
    """
    response = {"data": []}

    if filter is not None:
        if "dtree_id" in filter:
            response = API_RESPONSE["file_service.snapshots.dtree"]
        else:
            response = API_RESPONSE["file_service.snapshots.fs"]

    return (0, response)


class StorageTest(TestCase):
    """
    Tests for various storage functions in the oceanstor lib.
    """

    rest_client = mock.Mock()
    session = rest_client.return_value
    # static queries
    session.api.v2.account.accounts.get.return_value = (0, API_RESPONSE["account.accounts"])
    session.api.v2.data_service.storagepool.get.return_value = (0, API_RESPONSE["data_service.storagepool"])
    session.api.v2.converged_service.namespaces.get.return_value = (0, API_RESPONSE["converged_service.namespaces"])
    session.api.v2.file_service.snapshots.post.return_value = (0, API_RESPONSE["file_service.snapshots.post"])
    session.api.v2.file_service.snapshots.delete.return_value = (0, API_RESPONSE["file_service.snapshots.delete"])
    # queries related to dtrees have variable outcome depending on arguments
    session.api.v2.get.side_effect = api_response_get_side_effect
    session.api.v2.file_service.dtrees.get.side_effect = api_response_dtree_side_effect
    session.api.v2.file_service.snapshots.get.side_effect = api_response_snapshots_side_effect

    @mock.patch("vsc.filesystem.oceanstor.OceanStorRestClient", rest_client)
    def test_list_storage_pools(self):
        O = oceanstor.OceanStorOperations(*FAKE_INIT_PARAMS)
        storagepools_reference = {
            "StoragePool0": {
                "storagePoolId": 0,
                "storagePoolName": "StoragePool0",
            },
        }
        self.assertEqual(O.list_storage_pools(), storagepools_reference)
        storagepools_outdated = {
            "OutdatedStoragePool": {
                "storagePoolId": 1,
                "storagePoolName": "OutdatedStoragePool",
            },
        }
        O.oceanstor_storagepools = storagepools_outdated
        self.assertEqual(O.list_storage_pools(), storagepools_outdated)
        self.assertEqual(O.list_storage_pools(update=True), storagepools_reference)

    @mock.patch("vsc.filesystem.oceanstor.OceanStorRestClient", rest_client)
    def test_list_filesystems(self):
        O = oceanstor.OceanStorOperations(*FAKE_INIT_PARAMS)
        fs_test = {
            "test": {
                "id": 30,
                "name": "test",
                "storage_pool_id": 0,
            }
        }
        fs_data = {
            "data": {
                "id": 40,
                "name": "data",
                "storage_pool_id": 0,
            },
        }

        fs_reference = {}
        fs_reference.update(fs_test)
        self.assertEqual(O.list_filesystems(device="test"), fs_reference)
        self.assertEqual(O.list_filesystems(device="test", pool="StoragePool0"), fs_reference)

        fs_reference.update(fs_data)
        self.assertEqual(O.list_filesystems(), fs_reference)
        self.assertEqual(O.list_filesystems(pool="StoragePool0"), fs_reference)

        fs_outdated = {
            "outdated": {
                "id": 00,
                "name": "outdated",
                "storage_pool_id": 0,
            },
        }
        O.oceanstor_filesystems = fs_outdated
        self.assertEqual(O.list_filesystems(), fs_outdated)
        self.assertEqual(O.list_filesystems(update=True), fs_reference)

    @mock.patch("vsc.filesystem.oceanstor.OceanStorRestClient", rest_client)
    def test_get_filesystem_info(self):
        O = oceanstor.OceanStorOperations(*FAKE_INIT_PARAMS)
        fs_test = {
            "id": 30,
            "name": "test",
            "storage_pool_id": 0,
        }
        self.assertEqual(O.get_filesystem_info("test"), fs_test)
        self.assertRaises(oceanstor.OceanStorOperationError, O.get_filesystem_info, "nonexistent")

    @mock.patch("vsc.filesystem.oceanstor.OceanStorRestClient", rest_client)
    def test_list_filesets(self):
        O = oceanstor.OceanStorOperations(*FAKE_INIT_PARAMS)
        dt_test = {
            "30@4097": {
                "group": "",
                "id": "30@4097",
                "name": "dttest",
                "owner": "",
                "parent_dir": "/test",
            },
        }
        dt_test2 = {
            "30@4098": {
                "group": "",
                "id": "30@4098",
                "name": "dttest2",
                "owner": "",
                "parent_dir": "/test",
            },
        }
        dt_users = {
            "30@40963": {
                "group": "",
                "id": "30@40963",
                "name": "100",
                "owner": "",
                "parent_dir": "/test",
            },
        }

        dt_reference = {"test": {}}
        self.assertEqual(O.list_filesets(devices="test", filesetnames="nonexistent"), dt_reference)

        dt_reference["test"].update(dt_test)
        self.assertEqual(O.list_filesets(devices="test", filesetnames="dttest"), dt_reference)
        self.assertEqual(O.list_filesets(devices="test", filesetnames="dttest", pool="StoragePool0"), dt_reference)

        dt_reference["test"].update(dt_test2)
        self.assertEqual(O.list_filesets(devices="test", filesetnames=["dttest", "dttest2"]), dt_reference)

        dt_reference["test"].update(dt_users)
        self.assertEqual(O.list_filesets(devices="test"), dt_reference)

        dt_reference.update({"data": {}})
        self.assertEqual(O.list_filesets(), dt_reference)

        self.assertEqual(O.list_filesets(filesetnames="dttest"), {"data": {}, "test": dt_test})
        self.assertEqual(O.list_filesets(filesetnames="100"), {"data": {}, "test": dt_users})
        self.assertEqual(O.list_filesets(filesetnames="vsc100"), {"data": {}, "test": dt_users})

        dt_outdated = {
            "data": {},
            "test": {
                "30@00001": {
                    "group": "",
                    "id": "30@00001",
                    "name": "outdated",
                    "owner": "",
                    "parent_dir": "/test",
                },
            },
        }
        O.oceanstor_filesets = dt_outdated
        self.assertEqual(O.list_filesets(), dt_outdated)
        self.assertEqual(O.list_filesets(devices="test", filesetnames="dttest"), {"test": {}})
        self.assertEqual(O.list_filesets(devices="test", filesetnames="dttest", update=True), {"test": dt_test})
        self.assertEqual(O.list_filesets(update=True), dt_reference)

    @mock.patch("vsc.filesystem.oceanstor.OceanStorRestClient", rest_client)
    def test_get_fileset_info(self):
        O = oceanstor.OceanStorOperations(*FAKE_INIT_PARAMS)
        dt_test = {
            "group": "",
            "id": "30@4097",
            "name": "dttest",
            "owner": "",
            "parent_dir": "/test",
        }
        dt_users = {
            "group": "",
            "id": "30@40963",
            "name": "100",
            "owner": "",
            "parent_dir": "/test",
        }

        self.assertEqual(O.get_fileset_info("test", "dttest"), dt_test)
        self.assertEqual(O.get_fileset_info("test", "nonexistent"), None)
        self.assertEqual(O.get_fileset_info("test", "100"), dt_users)
        self.assertEqual(O.get_fileset_info("test", "vsc100"), dt_users)

    @mock.patch("vsc.filesystem.oceanstor.OceanStorRestClient", rest_client)
    def test_list_snapshots(self):
        O = oceanstor.OceanStorOperations(*FAKE_INIT_PARAMS)
        snap_reference = ["SNAP_TEST_01", "SNAP_TEST_02"]
        self.assertEqual(O.list_snapshots("test"), snap_reference)
        self.assertRaises(oceanstor.OceanStorOperationError, O.list_snapshots, "nonexistent")

        snap_reference = ["dttest_SNAP_TEST_01", "dttest_SNAP_TEST_03"]
        self.assertEqual(O.list_snapshots("test", "dttest"), snap_reference)
        self.assertRaises(oceanstor.OceanStorOperationError, O.list_snapshots, "test", "nonexistent")

    @mock.patch("vsc.filesystem.oceanstor.OceanStorRestClient", rest_client)
    def test_create_filesystem_snapshot(self):
        O = oceanstor.OceanStorOperations(*FAKE_INIT_PARAMS)
        self.assertEqual(O.create_filesystem_snapshot("test", "NEW_SNAPSHOT"), True)
        self.assertEqual(O.create_filesystem_snapshot("test", "SNAP_TEST_01"), 0)
        self.assertRaises(
            oceanstor.OceanStorOperationError, O.create_filesystem_snapshot, "nonexistent", "NEW_SNAPSHOT"
        )
        self.assertEqual(O.create_filesystem_snapshot("test", "NEW_SNAPSHOT", filesets="dttest"), True)
        self.assertEqual(O.create_filesystem_snapshot("test", "SNAP_TEST_01", filesets="dttest"), 0)
        self.assertEqual(O.create_filesystem_snapshot("test", "NEW_SNAPSHOT", filesets=["dttest"]), True)
        self.assertEqual(O.create_filesystem_snapshot("test", "SNAP_TEST_01", filesets=["dttest"]), 0)

    @mock.patch("vsc.filesystem.oceanstor.OceanStorRestClient", rest_client)
    def test_delete_filesystem_snapshot(self):
        O = oceanstor.OceanStorOperations(*FAKE_INIT_PARAMS)
        self.assertEqual(O.delete_filesystem_snapshot("test", "SNAP_TEST_01"), True)
        self.assertEqual(O.delete_filesystem_snapshot("test", "NONEXISTENT"), 0)
        self.assertRaises(
            oceanstor.OceanStorOperationError, O.delete_filesystem_snapshot, "nonexistent", "SNAP_TEST_01"
        )
