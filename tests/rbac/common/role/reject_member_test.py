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
"""Reject Role Add Member Test"""
# pylint: disable=no-member

import logging
import pytest

from rbac.common import rbac
from rbac.common import protobuf
from tests.rbac.common import helper

LOGGER = logging.getLogger(__name__)


@pytest.mark.role
@pytest.mark.library
def test_make():
    """Test making the message"""
    user_id = helper.user.id()
    role_id = helper.role.id()
    proposal_id = helper.proposal.id()
    reason = helper.proposal.reason()
    message = rbac.role.member.reject.make(
        proposal_id=proposal_id, user_id=user_id, role_id=role_id, reason=reason
    )
    assert isinstance(message, protobuf.role_transaction_pb2.RejectAddRoleMember)
    assert message.proposal_id == proposal_id
    assert message.user_id == user_id
    assert message.role_id == role_id
    assert message.reason == reason


@pytest.mark.role
@pytest.mark.library
def test_make_addresses():
    """Test making the message addresses"""
    user_id = helper.user.id()
    role_id = helper.role.id()
    proposal_id = helper.proposal.id()
    proposal_address = rbac.role.member.propose.address(role_id, user_id)
    reason = helper.proposal.reason()
    signer_keypair = helper.user.key()
    signer_admin_address = rbac.role.admin.address(role_id, signer_keypair.public_key)
    signer_owner_address = rbac.role.owner.address(role_id, signer_keypair.public_key)
    signer_user_address = rbac.user.address(signer_keypair.public_key)
    message = rbac.role.member.reject.make(
        proposal_id=proposal_id, user_id=user_id, role_id=role_id, reason=reason
    )

    inputs, outputs = rbac.role.member.reject.make_addresses(
        message=message, signer_keypair=signer_keypair
    )

    assert signer_owner_address in inputs
    assert signer_admin_address in inputs
    assert signer_user_address in inputs
    assert proposal_address in inputs

    assert proposal_address in outputs


@pytest.mark.role
@pytest.mark.reject_role_member
def test_create():
    """Test executing the message on the blockchain"""
    proposal, _, _, role_owner_key, _, _ = helper.role.member.propose.create()

    reason = helper.role.member.propose.reason()
    message = rbac.role.member.reject.make(
        proposal_id=proposal.proposal_id,
        role_id=proposal.object_id,
        user_id=proposal.related_id,
        reason=reason,
    )

    status = rbac.role.member.reject.new(
        signer_keypair=role_owner_key,
        message=message,
        object_id=proposal.object_id,
        related_id=proposal.related_id,
    )

    assert len(status) == 1
    assert status[0]["status"] == "COMMITTED"

    reject = rbac.role.member.propose.get(
        object_id=proposal.object_id, related_id=proposal.related_id
    )

    assert isinstance(reject, protobuf.proposal_state_pb2.Proposal)
    assert reject.proposal_type == protobuf.proposal_state_pb2.Proposal.ADD_ROLE_MEMBER
    assert reject.proposal_id == proposal.proposal_id
    assert reject.object_id == proposal.object_id
    assert reject.related_id == proposal.related_id
    assert reject.close_reason == reason
    assert reject.closer == role_owner_key.public_key
    assert reject.status == protobuf.proposal_state_pb2.Proposal.REJECTED
