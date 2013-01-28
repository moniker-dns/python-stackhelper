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
import abc
from cliff.command import Command as CliffCommand
from novaclient.v1_1 import Client as NovaClient

_NOVACLIENT = None


class Command(CliffCommand):
    __metaclass__ = abc.ABCMeta

    def run(self, parsed_args):
        return super(Command, self).run(parsed_args)

    @property
    def novaclient(self):
        global _NOVACLIENT

        if not _NOVACLIENT:
            novaclient_args = {
                'auth_url': self.app.options.os_auth_url,
                'username': self.app.options.os_username,
                'api_key': self.app.options.os_password,
                'project_id': self.app.options.os_tenant_name,
                'region_name': self.app.options.os_region_name,
            }

            _NOVACLIENT = NovaClient(**novaclient_args)

        return _NOVACLIENT

    @abc.abstractmethod
    def execute(self, parsed_args):
        """
        Execute something, this is since we overload self.take_action()
        in order to format the data

        This method __NEEDS__ to be overloaded!

        :param parsed_args: The parsed args that are given by take_action()
        """

    def post_execute(self, data):
        """
        Format the results locally if needed, by default we just return data

        :param data: Whatever is returned by self.execute()
        """
        return data

    def take_action(self, parsed_args):
        # TODO: Common Exception Handling Here
        results = self.execute(parsed_args)
        return self.post_execute(results)
