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

from rbac.providers.ldap import ldap_message_validator
from rbac.providers.error.validation import LdapValidationException


def test_validate_missing_data_type():
    ldap_payload = {"data": {"distinguished_name": "yo"}}

    try:
        ldap_message_validator.validate(ldap_payload)
    except LdapValidationException as lde:
        assert str(lde) == "Required field: 'data_type' is missing"


def test_validate_missing_data_field():
    ldap_payload = {"data_type": "user"}

    try:
        ldap_message_validator.validate(ldap_payload)
    except LdapValidationException as lde:
        assert str(lde) == "Required field: 'data' is missing"


def test_validate_invalid_data_type():
    ldap_payload = {"data": {"distinguished_name": "yo"}, "data_type": "no"}

    try:
        ldap_message_validator.validate(ldap_payload)
    except LdapValidationException as lde:
        assert (
            str(lde)
            == "Invalid value for 'data_type'. 'data_type' must be in: ['user', 'group']"
        )


def test_validate_missing_distinguished_name():
    ldap_payload = {"data": {}, "data_type": "user"}

    try:
        ldap_message_validator.validate(ldap_payload)
    except LdapValidationException as lde:
        assert str(lde) == "'data' is missing an entry for: 'distinguished_name'"


def test_validate_empty_distinguished_name():
    ldap_payload = {"data": {"distinguished_name": ""}, "data_type": "user"}

    try:
        ldap_message_validator.validate(ldap_payload)
    except LdapValidationException as lde:
        assert str(lde) == "'data'.'distinguished_name' cannot be empty"
