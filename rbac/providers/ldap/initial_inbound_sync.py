#! /usr/bin/env python3

# Copyright 2018 Contributors to Hyperledger Sawtooth
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
""" LDAP inbound initial sync
"""

import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone

import ldap3
import rethinkdb as r

from rbac.providers.common.common import check_last_sync
from rbac.providers.common.db_queries import connect_to_db, save_sync_time
from rbac.providers.common import ldap_connector
from rbac.providers.common.inbound_filters import (
    inbound_user_filter,
    inbound_group_filter,
)
from rbac.providers.common.rbac_transactions import add_transaction
from rbac.providers.ldap.delta_inbound_sync import inbound_delta_sync

LOGGER = logging.getLogger(__name__)
LOGGER.level = logging.INFO
LOGGER.addHandler(logging.StreamHandler(sys.stdout))

DB_HOST = os.getenv("DB_HOST", "rethink")
DB_PORT = int(os.getenv("DB_PORT", "28015"))
DB_NAME = os.getenv("DB_NAME", "rbac")

LDAP_DC = os.getenv("LDAP_DC")
LDAP_SERVER = os.getenv("LDAP_SERVER")
LDAP_USER = os.getenv("LDAP_USER")
LDAP_PASS = os.getenv("LDAP_PASS")

LDAP_SEARCH_PAGE_SIZE = 500


def fetch_ldap_data(data_type):
    """
        Call to get entries for all (Users | Groups) in Active Directory, saves the time of the sync,
        inserts data into RethinkDB, and initiates a new thread for a delta sync for data_type.
    """
    connect_to_db()

    if data_type == "user":
        search_filter = "(objectClass=person)"
    elif data_type == "group":
        search_filter = "(objectClass=group)"

    ldap_connection = ldap_connector.await_connection(LDAP_SERVER, LDAP_USER, LDAP_PASS)

    if ldap_connection is None:
        LOGGER.error("Ldap connection creation failed. Skipping Ldap fetch")
    else:

        search_parameters = {
            "search_base": LDAP_DC,
            "search_filter": search_filter,
            "attributes": ldap3.ALL_ATTRIBUTES,
            "paged_size": LDAP_SEARCH_PAGE_SIZE,
        }

        index = 1
        while True:

            ldap_connection.search(**search_parameters)
            for entry in ldap_connection.entries:

                index = index + 1
                if index % LDAP_SEARCH_PAGE_SIZE == 0:
                    LOGGER.info("Processing record: %s", index)

                insert_to_db(entry, data_type=data_type)

                # 1.2.840.113556.1.4.319 is the OID/extended control for PagedResults
                cookie = ldap_connection.result["controls"]["1.2.840.113556.1.4.319"][
                    "value"
                ]["cookie"]
                if cookie:
                    search_parameters["paged_cookie"] = cookie
                else:
                    LOGGER.info("Imported %s entries from Active Directory", index)
                    break

    sync_source = "ldap-" + data_type
    save_sync_time(LDAP_DC, sync_source, "initial")


def insert_to_db(entry, data_type):
    """Insert user or group individually to RethinkDB from dict of data and begins delta sync timer."""

    entry_json = json.loads(entry.entry_to_json())
    entry_attributes = entry_json["attributes"]

    for attribute in entry_attributes:

        try:
            if len(entry_attributes[attribute]) > 1:
                entry[attribute] = entry_attributes[attribute]
            else:
                entry[attribute] = entry_attributes[attribute][0]
        except TypeError:
            # TODO: There are a lot of mapping attempts that end up in this block. Revisit'
            LOGGER.warning("Could not assign: %s", entry_attributes[attribute][0])

    if data_type == "user":
        standardized_entry = inbound_user_filter(entry, "ldap")
    elif data_type == "group":
        standardized_entry = inbound_group_filter(entry, "ldap")
    inbound_entry = {
        "data": standardized_entry,
        "data_type": data_type,
        "sync_type": "initial",
        "timestamp": datetime.now().replace(tzinfo=timezone.utc).isoformat(),
        "provider_id": LDAP_DC,
        "raw": entry_json,
    }
    add_transaction(inbound_entry)
    r.table("inbound_queue").insert(inbound_entry).run()


def initiate_delta_sync():
    """Starts a new delta sync thread for LDAP data_type."""
    threading.Thread(target=inbound_delta_sync).start()


def initialize_ldap_sync():
    """
        Checks if LDAP initial syncs has been ran. If not, run initial sync for both ldap users
        and groups. If initial syncs have been completed, restart the inbound delta syncs.
    """

    if not LDAP_DC:
        LOGGER.info("Ldap Domain Controller is not provided, skipping Ldap sync.")
    elif not ldap_connector.can_connect_to_ldap(LDAP_SERVER, LDAP_USER, LDAP_PASS):
        LOGGER.info("Ldap Connection failed. Skipping Ldap sync.")
    else:

        connect_to_db()

        # Check to see if User Sync has occurred.  If not - Sync
        db_user_payload = check_last_sync("ldap-user", "initial")
        if not db_user_payload:
            LOGGER.info(
                "No initial AD user sync was found. Starting initial AD user sync now."
            )

            LOGGER.info("Getting AD Users...")
            fetch_ldap_data(data_type="user")

            LOGGER.info("Initial AD user upload completed.")

        # Check to see if Group Sync has occurred.  If not - Sync
        db_group_payload = check_last_sync("ldap-group", "initial")
        if not db_group_payload:
            LOGGER.info(
                "No initial AD group sync was found. Starting initial AD group sync now."
            )
            LOGGER.info("Getting Groups with Members...")
            fetch_ldap_data(data_type="group")

            LOGGER.info("Initial AD group upload completed.")

        if db_user_payload and db_group_payload:
            LOGGER.info("The LDAP initial sync has already been run.")

        # Start the inbound delta sync
        initiate_delta_sync()
