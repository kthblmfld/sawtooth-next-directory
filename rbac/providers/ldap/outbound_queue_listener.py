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
import time

import rethinkdb as r
from tornado import gen

from rbac.providers.error.validation import LdapValidationException
from rbac.providers.ldap.delta_outbound_sync import process_entry
from rbac.providers.ldap.ldap_message_validator import validate

LOGGER = logging.getLogger(__name__)

DB_HOST = "rethink"
DB_PORT = 28015
DB_NAME = "rbac"
DB_TABLE = "queue_outbound"
RETRY_INTERVAL_SECONDS_TABLE_READY = 3

r.set_loop_type("tornado")


@gen.coroutine
def export_feed_change_to_ldap():
    connected = False
    feed = None
    rethink_header = "new_val"

    while not connected:
        try:
            connection = yield r.connect(DB_HOST, DB_PORT, DB_NAME)
            feed = yield r.table(DB_TABLE).changes().run(connection)
            connected = True
        except r.ReqlRuntimeError as re:
            LOGGER.info(
                "Attempt to connect to %s threw exception: %s. Retrying in %s seconds",
                DB_TABLE,
                str(re),
                RETRY_INTERVAL_SECONDS_TABLE_READY,
            )
            time.sleep(RETRY_INTERVAL_SECONDS_TABLE_READY)

    while (yield feed.fetch_next()):
        new_record = yield feed.next()
        content = new_record[rethink_header]

        try:
            validate(content)
            process_entry(content, r)
        except LdapValidationException as le:
            # TODO: Determine what to do with inadequate ldap data in the queue. Log and drop?
            LOGGER.error(
                "Ldap payload: %s encountered a validation error: %s", content, le
            )
