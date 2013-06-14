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
import logging
import json
import copy
from stackhelper.cli import base

LOG = logging.getLogger(__name__)


class SecgroupSyncCommand(base.Command):
    """ Sync Security Groups """

    def get_parser(self, prog_name):
        parser = super(SecgroupSyncCommand, self).get_parser(prog_name)

        parser.add_argument('--secgroup-json', help="Path to security group JSON", required=True)
        parser.add_argument('--additional-group-json', help="Path to security group additional IPs JSON")  # What a name...
        parser.add_argument('--skip-deletes', help="skip and group/rule deletes", action="store_true")

        return parser

    def execute(self, parsed_args):
        config = self._parse_configuration(parsed_args)

        # Grab the list of currently active groups from nova
        config_groups = config['groups']
        config_group_names = config_groups.keys()
        server_groups = self.novaclient.security_groups.list()
        server_group_names = [group.name for group in server_groups]

        # First up, delete un-necessary groups.
        delete_groups = [group for group in server_groups if group.name not in config_group_names]

        for group in delete_groups:
            if parsed_args.skip_deletes:
                LOG.warn('SKIPPING Deleting group: %s' % group.name)
            else:
                LOG.warn('Deleting group: %s' % group.name)
                self.novaclient.security_groups.delete(group)

        # Refresh the list of groups
        server_groups = self.novaclient.security_groups.list()
        server_group_names = [group.name for group in server_groups]

        # Next up, Create missing groups
        create_groups = set(config_group_names).difference(server_group_names)

        for group_name in create_groups:
            # Fetch a copy of the groups config
            group_config = config_groups[group_name]

            LOG.info('Creating group: %s' % group_name)
            self.novaclient.security_groups.create(group_name, group_config['description'])

        # Refresh the list of groups
        server_groups = self.novaclient.security_groups.list()
        server_group_names = [group.name for group in server_groups]
        server_group_ids = dict((server_group.name, server_group.id) for server_group in server_groups)

        # Next Up, sync rules
        for server_group in server_groups:
            # Fetch a copy of the group config
            config_group = config_groups.get(server_group.name, {})
            config_rules = config_group.get('rules', [])
            server_rules = server_group.rules

            # Delete out of date rules
            for server_rule in server_rules:
                if not self._config_has_rule(server_group_ids, config_rules, server_rule):
                    log_msg = ("Delete rule ALLOW %s/%s-%s in group '%s'" %
                            (server_rule['ip_protocol'],
                             server_rule['from_port'],
                             server_rule['to_port'],
                             server_group.name))

                    if parsed_args.skip_deletes:
                        LOG.info("SKIPPING %s" % log_msg)
                    else:
                        LOG.info(log_msg)
                        self.novaclient.security_group_rules.delete(server_rule['id'])

            # Create missing rules
            for config_rule in config_rules:
                if not self._server_has_rule(server_group_ids, server_rules, config_rule):
                    cidr = None
                    group_id = None

                    if config_rule.get('group'):
                        group_id = server_group_ids[config_rule['group']]
                        LOG.info("Create rule ALLOW %s/%s-%s FROM '%s' in group '%s'" %
                            (config_rule['ip_protocol'],
                             config_rule['from_port'],
                             config_rule['to_port'],
                             config_rule['group'],
                             server_group.name))

                    else:
                        cidr = config_rule['cidr']
                        LOG.info("Create rule ALLOW %s/%s-%s FROM '%s' in group '%s'" %
                            (config_rule['ip_protocol'],
                             config_rule['from_port'],
                             config_rule['to_port'],
                             cidr,
                             server_group.name))

                    self.novaclient.security_group_rules.create(
                        server_group.id,
                        config_rule['ip_protocol'],
                        config_rule['from_port'],
                        config_rule['to_port'],
                        cidr,
                        group_id)

    def _parse_configuration(self, parsed_args):
        # Read the main config file
        with open(parsed_args.secgroup_json) as fh:
            config = json.load(fh)

        # Load up the group additions
        additional_group_ips = {}

        if parsed_args.additional_group_json:
            with open(parsed_args.additional_group_json) as fh:
                additional_group_ips = json.load(fh)

            # Inject rules for each of the additional group IPs
            for group in config['groups']:
                additional_rules = []

                for rule in config['groups'][group]['rules']:
                    if 'group' in rule and rule['group'] in additional_group_ips:
                        for ip in additional_group_ips[rule['group']]:
                            new_rule = copy.copy(rule)
                            del new_rule['group']
                            new_rule['cidr'] = '%s/32' % ip
                            additional_rules.append(new_rule)

                config['groups'][group]['rules'].extend(additional_rules)

        return config

    def _server_has_rule(self, server_group_ids, server_rules, config_rule):
        for server_rule in server_rules:
            matched = self._compare_rule(server_group_ids, server_rule, config_rule)

            if matched:
                return matched

        return False

    def _config_has_rule(self, server_group_ids, config_rules, server_rule):
        for config_rule in config_rules:
            matched = self._compare_rule(server_group_ids, server_rule, config_rule)

            if matched:
                return matched

        return False

    def _compare_rule(self, server_group_ids, server_rule, config_rule):
        if (server_rule['ip_protocol'] == config_rule['ip_protocol'] and
            server_rule['from_port'] == config_rule['from_port'] and
            server_rule['to_port'] == config_rule['to_port']):

            try:
                if server_rule['ip_range']['cidr'] == config_rule['cidr']:
                    return True
            except KeyError:
                pass

            try:
                if server_rule['group']['name'] == config_rule['group']:
                    return True
            except KeyError:
                pass

        return False
