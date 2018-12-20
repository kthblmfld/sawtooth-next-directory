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
"""Addresses and accesses task objects on the blockchain"""
# pylint: disable=unused-import

from rbac.common import addresser
from rbac.common.base.base_address import AddressBase
from rbac.common.base.base_relationship import BaseRelationship
from rbac.common.protobuf import task_state_pb2
from rbac.common.protobuf import task_transaction_pb2


class TaskOwnerAddress(BaseRelationship):
    """Addresses and accesses the role owner relationship"""

    def __init__(self):
        super().__init__()
        self._register()

    @property
    def address_type(self):
        """The address type from AddressSpace implemented by this class"""
        return addresser.AddressSpace.TASKS_OWNERS

    @property
    def object_type(self):
        """The object type from AddressSpace implemented by this class"""
        return addresser.ObjectType.TASK

    @property
    def related_type(self):
        """The related type from AddressSpace implemented by this class"""
        return addresser.ObjectType.USER

    @property
    def relationship_type(self):
        """The related type from AddressSpace implemented by this class"""
        return addresser.RelationshipType.OWNER


class TaskAdminAddress(BaseRelationship):
    """Addresses and accesses the role admin relationship"""

    def __init__(self):
        super().__init__()
        self._register()

    @property
    def address_type(self):
        """The address type from AddressSpace implemented by this class"""
        return addresser.AddressSpace.TASKS_ADMINS

    @property
    def object_type(self):
        """The object type from AddressSpace implemented by this class"""
        return addresser.ObjectType.TASK

    @property
    def related_type(self):
        """The related type from AddressSpace implemented by this class"""
        return addresser.ObjectType.USER

    @property
    def relationship_type(self):
        """The related type from AddressSpace implemented by this class"""
        return addresser.RelationshipType.ADMIN


class TaskAddress(AddressBase):
    """Addresses and accesses task objects on the blockchain"""

    def __init__(self):
        super().__init__()
        self._register()
        self.owner = TaskOwnerAddress()
        self.admin = TaskAdminAddress()

    @property
    def address_type(self):
        """The address type from AddressSpace implemented by this class"""
        return addresser.AddressSpace.TASKS_ATTRIBUTES

    @property
    def object_type(self):
        """The object type from AddressSpace implemented by this class"""
        return addresser.ObjectType.TASK

    @property
    def related_type(self):
        """The related type from AddressSpace implemented by this class"""
        return addresser.ObjectType.NONE

    @property
    def relationship_type(self):
        """The related type from AddressSpace implemented by this class"""
        return addresser.RelationshipType.ATTRIBUTES

    @property
    def _state_object_name(self):
        """Tasks state object name ends with Attributes (TaskAttributes)"""
        return self._name_camel + "Attributes"

    @property
    def _state_container_list_name(self):
        """Tasks state container collection name contains _attributes (task_attributes)"""
        return self._name_lower + "_attributes"


TASK_ADDRESS = TaskAddress()

__all__ = ["TASK_ADDRESS"]
