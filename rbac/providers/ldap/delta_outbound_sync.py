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
# ------------------------------------------------------------------------------

import logging
import os

import ldap3
from ldap3 import ALL, MODIFY_REPLACE, Connection, Server
from ldap3.core.exceptions import LDAPInvalidDnError, LDAPSocketOpenError

from rbac.providers.common.rethink_db import put_entry_changelog, delete_entry_queue
from rbac.providers.common.outbound_filters import (
    outbound_user_filter,
    outbound_group_filter,
)

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


LDAP_DC = os.environ.get("LDAP_DC")
LDAP_SERVER = os.environ.get("LDAP_SERVER")
LDAP_USER = os.environ.get("LDAP_USER")
LDAP_PASS = os.environ.get("LDAP_PASS")
DIRECTION = "outbound"

USER_SEARCH_FILTER = "(&(objectClass=person)(distinguishedName={}))"
GROUP_SEARCH_FILTER = "(&(objectClass=group)(distinguishedName={}))"

USER_REQUIRED_ATTR = {"cn"}
GROUP_REQUIRED_ATTR = {"groupType"}
LDAP_CONNECT_TIMEOUT_SECONDS = 5
LDAP_RECEIVE_TIMEOUT_SECONDS = 5


def process_entry(queue_entry, outbound_queue):
    """
        Process outbound_entry as a AD user or AD group. If entry is neither,
        throw ValueError.
    """
    LOGGER.info("Publishing to ldap: %s", queue_entry)
    ldap_conn = connect_to_ldap()

    if ldap_conn:
        # TODO: Should we remove the record if it fails? Move it to a retry queue?
        #       Wrapped as-is: A failure from Ldap will propagate out before the db record removal step
        # TODO: Share allowed data_type values with those defined in ldap_message_validator
        LOGGER.info(
            "Connected to ldap. Transmitting message, recording to changelog, deleting record..."
        )

        try:
            if is_entry_in_ad(queue_entry, ldap_conn):
                update_entry_ldap(queue_entry, ldap_conn)
            else:
                create_entry_ldap(queue_entry, ldap_conn)
            put_entry_changelog(queue_entry, DIRECTION)
            queue_entry_id = queue_entry["id"]
            delete_entry_queue(queue_entry_id, outbound_queue)
        except LDAPInvalidDnError as edn:
            LOGGER.error("Encountered an error sending message to ldap. Error: %s", edn)


def connect_to_ldap():
    """
        Creates a connection to LDAP server and returns the connection object.
    """
    # FIXME: connect_timeout is not being honored while trying to send record from off-network
    server = Server(
        host=LDAP_SERVER, get_info=ALL, connect_timeout=LDAP_CONNECT_TIMEOUT_SECONDS
    )
    ldap_conn = Connection(
        server,
        user=LDAP_USER,
        password=LDAP_PASS,
        receive_timeout=LDAP_RECEIVE_TIMEOUT_SECONDS,
    )
    try:
        ldap_conn.bind()
    except LDAPSocketOpenError as lse:
        LOGGER.error(
            "Failed to open a connection to Ldap. Aborting message transmission. Error: %s",
            lse,
        )
    return ldap_conn


def is_entry_in_ad(queue_entry, ldap_conn):
    """
        Searches AD to see if queue_entry already exists. Returns
        True if the entry does exist.
    """
    data_type = queue_entry["data_type"]
    queue_entry_data = queue_entry["data"]
    distinguished_name = queue_entry_data["distinguished_name"][0]

    if data_type == "user":
        LOGGER.debug("Querying ldap for user...")
        search_filter = USER_SEARCH_FILTER.format(distinguished_name)
    elif data_type == "group":
        LOGGER.debug("Querying ldap for group...")
        search_filter = GROUP_SEARCH_FILTER.format(distinguished_name)
    else:
        # This case should be caught by the validator. But just in case...
        LOGGER.warning(
            "Outbound queue record does not contain proper data type: %s", data_type
        )

    ldap_conn.search(
        search_base=LDAP_DC,
        search_filter=search_filter,
        attributes=ldap3.ALL_ATTRIBUTES,
    )
    return bool(ldap_conn.entries)


def update_entry_ldap(queue_entry, ldap_conn):
    """
        Routes the given queue entry to the proper handler to update the
        AD (user | group) in Active Directory.
    """
    data_type = queue_entry["data_type"]
    queue_entry_data = queue_entry["data"]

    if data_type == "user":
        update_user_ldap(sawtooth_entry=queue_entry_data, ldap_conn=ldap_conn)
    elif data_type == "group":
        update_group_ldap(sawtooth_entry=queue_entry_data, ldap_conn=ldap_conn)


def update_user_ldap(sawtooth_entry, ldap_conn):
    """Update existing AD user with any updated attributes from sawtooth_entry."""
    sawtooth_entry_filtered = outbound_user_filter(
        sawtooth_user=sawtooth_entry, provider="ldap"
    )
    modify_ad_attributes(sawtooth_entry_filtered, ldap_conn)
    LOGGER.debug("User updated in AD")


def update_group_ldap(sawtooth_entry, ldap_conn):
    """Update existing AD group with any updated attributes from sawtooth_entry."""
    sawtooth_entry_filtered = outbound_group_filter(sawtooth_entry, "ldap")
    modify_ad_attributes(sawtooth_entry_filtered, ldap_conn)
    LOGGER.debug("Group updated in AD")


def create_entry_ldap(queue_entry, ldap_conn):
    """
        Routes the given query entry to the proper handler to create the
        AD (user | group) in Active Directory.
    """
    data_type = queue_entry["data_type"]
    queue_entry_data = queue_entry["data"]

    if data_type == "user":
        create_user_ldap(sawtooth_entry=queue_entry_data, ldap_conn=ldap_conn)
    elif data_type == "group":
        create_group_ldap(sawtooth_entry=queue_entry_data, ldap_conn=ldap_conn)


def create_user_ldap(sawtooth_entry, ldap_conn):
    """Create new AD user using attributes from sawtooth_entry."""
    sawtooth_entry_filtered = outbound_user_filter(sawtooth_entry, "ldap")
    distinguished_name = sawtooth_entry_filtered["distinguishedName"][0]
    LOGGER.info("Creating new AD user: %s", distinguished_name)
    if all(attribute in sawtooth_entry_filtered for attribute in USER_REQUIRED_ATTR):
        ldap_conn.add(
            dn=distinguished_name,
            object_class={"person", "organizationalPerson", "user"},
            attributes={
                "cn": sawtooth_entry_filtered["cn"],
                "userPrincipalName": sawtooth_entry_filtered["userPrincipalName"],
            },
        )

        modify_ad_attributes(sawtooth_entry_filtered, ldap_conn)
        LOGGER.info("User created in AD")
    else:
        LOGGER.warning(
            "Cannot create a new user because required attributes were missing. Required attributes: %s",
            USER_REQUIRED_ATTR,
        )


def create_group_ldap(sawtooth_entry, ldap_conn):
    """Create new AD group using attributes from sawtooth_entry."""
    sawtooth_entry_filtered = outbound_group_filter(sawtooth_entry, "ldap")
    distinguished_name = sawtooth_entry_filtered["distinguishedName"][0]
    LOGGER.info("Creating new AD group: %s", distinguished_name)
    if all(attribute in sawtooth_entry_filtered for attribute in GROUP_REQUIRED_ATTR):
        ldap_conn.add(
            dn=distinguished_name,
            object_class={"group", "top"},
            attributes={"groupType": sawtooth_entry_filtered["groupType"]},
        )

        modify_ad_attributes(sawtooth_entry_filtered, ldap_conn)
        LOGGER.info("Group created in AD")
    else:
        LOGGER.warning(
            "Cannot create a new group because required attributes were missing. Required attributes: %s",
            GROUP_REQUIRED_ATTR,
        )


def modify_ad_attributes(sawtooth_entry_filtered, ldap_conn):
    """
        Modify the the (user | group) with the filtered attributes
        from sawtooth_entry.
    """
    distinguished_name = sawtooth_entry_filtered["distinguishedName"][0]
    for ad_attribute in sawtooth_entry_filtered:
        if ad_attribute == "member":
            ldap_conn.modify(
                dn=distinguished_name,
                changes={
                    ad_attribute: [
                        (MODIFY_REPLACE, [sawtooth_entry_filtered["member"]])
                    ]
                },
            )
        else:
            ldap_conn.modify(
                dn=distinguished_name,
                changes={
                    ad_attribute: [
                        (MODIFY_REPLACE, [sawtooth_entry_filtered[ad_attribute][0]])
                    ]
                },
            )
