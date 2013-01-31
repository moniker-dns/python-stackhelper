# Copyright 2012 Hewlett-Packard Development Company, L.P. All Rights Reserved.
#
# Author: Kiall Mac Innes <kiall@hp.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import os
import logging
import json
import keyring
from getpass import getpass
from stackhelper.cli import base

LOG = logging.getLogger(__name__)


class CredentialsCommand(base.Command):
    """ Active Credentials Management """

    def get_parser(self, prog_name):
        parser = super(CredentialsCommand, self).get_parser(prog_name)

        parser.add_argument('--credentials-json', help="Path to creds JSON", default='~/.stackhelper/credentials.json')
        parser.add_argument('service', help="Service")
        parser.add_argument('region', help="Region")
        parser.add_argument('account', help="Account")

        return parser

    def execute(self, parsed_args):
        # Load The Config File
        config_path = os.path.expanduser(parsed_args.credentials_json)

        with file(config_path) as fh:
            config = json.load(fh)

        try:
            service = config['services'][parsed_args.service]
            region = service['regions'][parsed_args.region]
            account = service['accounts'][parsed_args.account]
        except KeyError:
            raise Exception('Uh oh, Invalid Config File?')

        keyring_key = "%s/%s" % (parsed_args.service, parsed_args.account)
        password = None

        try:
            password = keyring.get_password("stackhelper", keyring_key)
        except keyring.backend.PasswordGetError:
            pass

        if not password:
            try:
                password = getpass('Please enter the password:')
            except KeyboardInterrupt:
                raise Exception('A password is required')

        # Store the password in the keyring
        try:
            keyring.set_password("stackhelper", keyring_key, password)
        except keyring.backend.PasswordSetError:
            LOG.warning('Unable to save password in keyring')

        environment = {
            'OS_AUTH_URL': None,
            'OS_USERNAME': None,
            'OS_PASSWORD': None,
            'OS_TENANT_ID': None,
            'OS_TENANT_NAME': None,
            'OS_SERVICE_TOKEN': None,
            'OS_REGION_NAME': None
        }

        environment.update(service['environment'])
        environment.update(region['environment'])
        environment.update(account['environment'])
        environment['OS_PASSWORD'] = password

        for key, value in environment.items():
            if value is None:
                continue

            print "export %s=%s" % (key, self.escape(value))

    def escape(self, value):
        """ How does python not have this built in??? """
        value = value.replace('`', '\`')
        value = value.replace('"', '\"')
        value = value.replace('$', '\$')
        value = value.replace('(', '\(')
        value = value.replace(')', '\)')
        return value
