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

# http://docs.python-requests.org/en/master/

import sys
import json
import logging
import requests
import time

LOGGER = logging.getLogger(__name__)
LOGGER.level = logging.DEBUG
LOGGER.addHandler(logging.StreamHandler(sys.stdout))

HEADERS = {"Content-Type": "application/json"}


def insert_test_data():
    """Inserts test users, managers, roles for demo and experimentation.

      Builds out an example user, manager, role structure by making rest calls against the NEXT api.
    """

    host = "localhost"

    custom_host = input("What is the hostname you would like to populate test "
                        "data to? Press enter for localhost: ")

    if custom_host:
        host = custom_host

    LOGGER.info("Inserting test data...")

    response_create_current_manager = create_user('currentManager', host)
    LOGGER.info('Created current manager:%s', response_create_current_manager)

    id_current_manager = response_create_current_manager['data']['user']['id']

    response_create_other_manager = create_user('otherManager', host)
    id_other_manager = response_create_other_manager['data']['user']['id']

    LOGGER.info('Created other manager:%s', response_create_other_manager)

    additional_managers = 5

    LOGGER.info('Adding an additional %s managers...', additional_managers)

    for i in range(additional_managers):
        create_user('manager' + str(i), host)

    response_create_staff = create_user('staff', host, id_current_manager)
    id_staff = response_create_staff['data']['user']['id']

    LOGGER.info('Created staff:%s', response_create_staff)

    auth_current_manager = response_create_current_manager['token']

    LOGGER.info('Creating roles...')

    role_name = "Mongers"

    LOGGER.info('Creating role: %s', role_name)

    response_create_role_sharepoint = create_role(auth=auth_current_manager,
                                                  name=role_name,
                                                  owners=[id_current_manager],
                                                  admins=[id_current_manager],
                                                  members=[id_staff],
                                                  host=host,
                                                  max_term_days=3)

    role_id = response_create_role_sharepoint['data']['id']

    LOGGER.info('Created role: %s with id: %s', response_create_role_sharepoint['data']['name'], role_id)
    LOGGER.info('Full response: %s', str(response_create_role_sharepoint))

    sleep_time = 5
    LOGGER.info('Waiting %s seconds for propagation....', sleep_time)
    time.sleep(sleep_time)

    LOGGER.info('Looking up role with id: %s', role_id)
    get_role_response = get_role(auth=auth_current_manager, host=host, role_id=role_id)

    # TODO: Not currently end-to-end (requires head block)
    # LOGGER.info('Getting all roles')
    # get_roles_response = get_roles(auth=auth_current_manager, host=host)

    LOGGER.info('Role lookup response: %s', str(get_role_response))

    # TODO: Uncomment and investigate the proposals defect these last steps cause
    # LOGGER.info('Creating role: Infosec Auditors')
    # response_create_role_infosec = create_role(auth=auth_current_manager,
    #                                            name="Infosec Auditors",
    #                                            owners=[id_current_manager],
    #                                            admins=[id_current_manager],
    #                                            members=[id_staff],
    #                                            host=host)
    #
    # LOGGER.info('Created role:%s', response_create_role_infosec['data']['name'])
    #
    # payload_id_of_new_manager_proposed = {"id": id_other_manager}
    #
    # uri_propose_new_manager = 'http://' + host + ':8000/api/users/' + id_staff + '/manager/'
    #
    # LOGGER.info('uri: ' + uri_propose_new_manager + '\npayload_id_of_new_manager_proposed: ' + str(
    #     payload_id_of_new_manager_proposed) + '\nmanager authorization: ' + str(auth_current_manager))
    #
    # response_propose_manager = json.loads(
    #     requests.put(uri_propose_new_manager, data=json.dumps(payload_id_of_new_manager_proposed),
    #                  headers={"Content-Type": "application/json",
    #                           "Authorization": auth_current_manager}).text)
    #
    # LOGGER.info('---- Propose manager response -----: %s', response_propose_manager)
    #
    # LOGGER.info('Created proposal id: %s - Switch %s\'s manager from %s to %s',
    #             response_propose_manager['proposal_id'],
    #             'staff',
    #             'currentManager',
    #             'otherManager')


def create_user(identifier, host, manager=''):
    """Creates a user in the system having the given identifier as name, password, username and *optional* manager

       Returns the response payload of the user creation rest call as a json object.
    """
    payload_current_manager = {'name': identifier, 'password': identifier, 'username': identifier,
                               'email': identifier + '@mail.com', 'manager': manager, 'metadata': ''}

    response_create_user = requests.post('http://' + host + ':8000/api/users/', json=payload_current_manager)
    return json.loads(response_create_user.text)


def get_role(auth, host, role_id):
    """Gets a role from the roles endpoint"""

    response = requests.get('http://' + host + ':8000/api/roles/' + role_id, headers={"Accept": "application/json",
                                                                                      "Authorization": auth})

    if response.status_code != 200:
        raise RuntimeError('Failed to get role. Response: ' + response.text)

    json.loads(response.text)


def get_roles(auth, host):
    """Gets all roles from the roles endpoint"""

    response = requests.get('http://' + host + ':8000/api/roles', headers={"Accept": "application/json",
                                                                           "Authorization": auth})

    if response.status_code != 200:
        raise RuntimeError('Failed to get roles. Response: ' + response.text)

    json.loads(response.text)


def create_role(auth, name, owners, admins, members, host, max_term_days=0):
    """Creates a role using the roles endpoint

       Args:
           auth: The bearer token to be used in the Authorization header
           name: The name of the role
           owners: Owners of the role (add/remove members)
           admins: Administrators of the role (modify the role itself)
           members: Members of the role (inherit the privileges assigned to the role)
           host: The target host

       Returns the response payload of the role creation rest call as a json object.
    """

    payload_create_role = {"name": name, "owners": owners, "administrators": admins, "members": members,
                           "metadata": "max_term_days=" + str(max_term_days)}

    response_create_role_envelope = requests.post('http://' + host + ':8000/api/roles/', json=payload_create_role,
                                                  headers={"Content-Type": "application/json",
                                                           "Authorization": auth})

    if response_create_role_envelope.status_code != 200:
        raise RuntimeError('Failed to create role. Response: ' + response_create_role_envelope.text)

    response_create_role_payload = json.loads(response_create_role_envelope.text)
    return response_create_role_payload


if __name__ == "__main__":
    insert_test_data()
