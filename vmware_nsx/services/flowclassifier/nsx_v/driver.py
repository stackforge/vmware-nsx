# Copyright 2016 VMware, Inc.
#
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from networking_sfc.services.flowclassifier.common import exceptions as exc
from networking_sfc.services.flowclassifier.drivers import base as fc_driver
from neutron import manager
from oslo_config import cfg
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
import xml.etree.ElementTree as et

from vmware_nsx._i18n import _
from vmware_nsx.common import config  # noqa
from vmware_nsx.common import exceptions as nsx_exc
from vmware_nsx.common import locking
from vmware_nsx.plugins.nsx_v.vshield import vcns as nsxv_api

LOG = logging.getLogger(__name__)

REDIRECT_FW_SECTION_NAME = 'Flow Classifier Rules'
MAX_PORTS_IN_RANGE = 15


class NsxvFlowClassifierDriver(fc_driver.FlowClassifierDriverBase):
    """FlowClassifier Driver For NSX-V."""

    _redirect_section_id = None

    @property
    def _core_plugin(self):
        return manager.NeutronManager.get_plugin()

    @property
    def _nsxv(self):
        return self._core_plugin.nsx_v

    def initialize(self):
        # TODO(asarfaty): In the future this may be a list if we support
        # multiple vendors
        if not cfg.CONF.nsxv.service_insertion_redirect_to:
            error = _("Cannot use the NSX-V Flow Classifier Driver without "
                      "setting the service insertion redirect to parameters")
            raise nsx_exc.NsxPluginException(err_msg=error)
        self._redirect_to = cfg.CONF.nsxv.service_insertion_redirect_to
        # DEBUG ADIT check that this value is legal???

    def get_redirect_fw_section_id(self):
        if not self._redirect_section_id:
            # try to find it
            self._redirect_section_id = self._nsxv.vcns.get_section_id(
                REDIRECT_FW_SECTION_NAME)
            if not self._redirect_section_id:
                # create it for the first time
                section = et.Element('section')
                section.attrib['name'] = REDIRECT_FW_SECTION_NAME
                sect = self._nsxv.vcns.create_redirect_section(
                    et.tostring(section))[1]
                self. _redirect_section_id = et.fromstring(sect).attrib['id']

        return self._redirect_section_id

    def get_redirect_fw_section_uri(self):
        return '%s/%s/%s' % (nsxv_api.FIREWALL_PREFIX,
                             nsxv_api.FIREWALL_REDIRECT_SEC_TYPE,
                             self.get_redirect_fw_section_id())

    def get_redirect_fw_section_from_backend(self):
        section_uri = self.get_redirect_fw_section_uri()
        xml_section = self._nsxv.vcns.get_section(section_uri)[1]
        return et.fromstring(xml_section)

    def update_redirect_fw_section_in_backed(self, section):
        section_uri = self.get_redirect_fw_section_uri()
        self._nsxv.vcns.update_section(
            section_uri,
            et.tostring(section, encoding="us-ascii"),
            None)

    def _rule_ip_type(self, flow_classifier):
        if flow_classifier.get('ethertype') == 'IPv4':
            return 'Ipv4Address'
        else:
            return 'Ipv6Address'

    def _rule_ports(self, type, flow_classifier):
        min_port = flow_classifier.get(type + '_port_range_min')
        max_port = flow_classifier.get(type + '_port_range_max')
        return self._ports_list(min_port, max_port)

    def _ports_list(self, min_port, max_port):
        """Return a string of comma separated ports. i.e. '80,81'
        """
        return str(range(min_port, max_port + 1))[1:-1]

    def _rule_name(self, flow_classifier):
        return flow_classifier.get('name') + '-' + flow_classifier.get('id')

    def _is_the_same_rule(self, rule, flow_classifier_id):
        return rule.find('name').text.endswith(flow_classifier_id)

    def init_redirect_fw_rule(self, redirect_rule, flow_classifier):
        # The name of the rule will include the name & id of the classifier
        # so we can later find it in order to update/delete it
        et.SubElement(redirect_rule, 'name').text = self._rule_name(
            flow_classifier)
        et.SubElement(redirect_rule, 'action').text = 'redirect'
        et.SubElement(redirect_rule, 'redirectTo').text = self._redirect_to
        et.SubElement(redirect_rule, 'packetType').text = flow_classifier.get(
            'ethertype').lower()

        # init the source & destination
        if flow_classifier.get('source_ip_prefix'):
            sources = et.SubElement(redirect_rule, 'sources')
            sources.attrib['excluded'] = 'false'
            source = et.SubElement(sources, 'source')
            et.SubElement(source, 'type').text = self._rule_ip_type(
                flow_classifier)
            et.SubElement(source, 'value').text = flow_classifier.get(
                'source_ip_prefix')

        if flow_classifier.get('destination_ip_prefix'):
            destinations = et.SubElement(redirect_rule, 'destinations')
            destinations.attrib['excluded'] = 'false'
            destination = et.SubElement(destinations, 'destination')
            et.SubElement(destination, 'type').text = self._rule_ip_type(
                flow_classifier)
            et.SubElement(destination, 'value').text = flow_classifier.get(
                'destination_ip_prefix')

        # init the service
        if (flow_classifier.get('destination_port_range_min') or
            flow_classifier.get('source_port_range_min')):
            services = et.SubElement(redirect_rule, 'services')
            service = et.SubElement(services, 'service')
            et.SubElement(service, 'isValid').text = 'true'
            if flow_classifier.get('source_port_range_min'):
                source_port = et.SubElement(service, 'sourcePort')
                source_port.text = self._rule_ports('source',
                                                    flow_classifier)

            if flow_classifier.get('destination_port_range_min'):
                dest_port = et.SubElement(service, 'destinationPort')
                dest_port.text = self._rule_ports('destination',
                                                  flow_classifier)

            prot = et.SubElement(service, 'protocolName')
            prot.text = flow_classifier.get('protocol').upper()

        # Add the classifier description
        if flow_classifier.get('description'):
            notes = et.SubElement(redirect_rule, 'notes')
            notes.text = flow_classifier.get('description')

    def _loc_fw_section(self):
        return locking.LockManager.get_lock('redirect-fw-section')

    def add_redirect_fw_rule(self, flow_classifier):
        with self._loc_fw_section():
            section = self.get_redirect_fw_section_from_backend()
            new_rule = et.SubElement(section, 'rule')
            self.init_redirect_fw_rule(new_rule, flow_classifier)
            self.update_redirect_fw_section_in_backed(section)

    def update_redirect_fw_rule(self, flow_classifier):
        with self._loc_fw_section():
            section = self.get_redirect_fw_section_from_backend()
            redirect_rule = None
            for rule in section.iter('rule'):
                if self._is_the_same_rule(rule, flow_classifier['id']):
                    redirect_rule = rule
                    break

            if redirect_rule is None:
                msg = _("Failed to find redirect rule %s "
                        "on backed") % flow_classifier['id']
                raise exc.FlowClassifierException(message=msg)
            else:
                # The plugin currently supports updating name or description
                name = redirect_rule.find('name')
                name.text = self._rule_name(flow_classifier)
                notes = redirect_rule.find('notes')
                notes.text = flow_classifier.get('description') or ''
                self.update_redirect_fw_section_in_backed(section)

    def delete_redirect_fw_rule(self, flow_classifier_id):
        with self._loc_fw_section():
            section = self.get_redirect_fw_section_from_backend()
            redirect_rule = None
            for rule in section.iter('rule'):
                if self._is_the_same_rule(rule, flow_classifier_id):
                    redirect_rule = rule
                    section.remove(redirect_rule)
                    break

            if redirect_rule is None:
                LOG.error("Failed to find redirect rule %s on backed",
                          flow_classifier_id)
                # should not fail the deletion
            else:
                self.update_redirect_fw_section_in_backed(section)

    @log_helpers.log_method_call
    def create_flow_classifier(self, context):
        # DEBUG ADIT create the policy at the backend (if option 2)
        flow_classifier = context.current
        self.add_redirect_fw_rule(flow_classifier)

    @log_helpers.log_method_call
    def update_flow_classifier(self, context):
        # DEBUG ADIT update the policy at the backend
        # (if option 2, or already assigned to the chain)
        flow_classifier = context.current
        self.update_redirect_fw_rule(flow_classifier)

    @log_helpers.log_method_call
    def delete_flow_classifier(self, context):
        # DEBUG ADIT delete the policy at the backend (if option 2)
        flow_classifier = context.current
        self.delete_redirect_fw_rule(flow_classifier['id'])

    @log_helpers.log_method_call
    def create_flow_classifier_precommit(self, context):
        """NSX-V Driver precommit before transaction committed.

        The NSX-v redirect rules does not support:
        - logical ports
        - l7 parameters
        - source ports range / dest port range with more than 15 ports
        """
        flow_classifier = context.current

        # Logical source port
        logical_source_port = flow_classifier['logical_source_port']
        if logical_source_port is not None:
            msg = _('The NSXv driver does not support setting '
                    'logical source port in FlowClassifier')
            raise exc.FlowClassifierBadRequest(message=msg)

        # Logical destination port
        logical_destination_port = flow_classifier['logical_destination_port']
        if logical_destination_port is not None:
            msg = _('The NSXv driver does not support setting '
                    'logical destination port in FlowClassifier')
            raise exc.FlowClassifierBadRequest(message=msg)

        # L7 parameters
        l7_params = flow_classifier['l7_parameters']
        if l7_params is not None and len(l7_params.keys()) > 0:
            msg = _('The NSXv driver does not support setting '
                    'L7 parameters in FlowClassifier')
            raise exc.FlowClassifierBadRequest(message=msg)

        # Source ports range - up to 15 ports.
        sport_min = flow_classifier['source_port_range_min']
        sport_max = flow_classifier['source_port_range_max']
        if (sport_min is not None and sport_max is not None and
            (sport_max + 1 - sport_min) > MAX_PORTS_IN_RANGE):
            msg = _('The NSXv driver does not support setting '
                    'more than %d source ports in a '
                    'FlowClassifier') % MAX_PORTS_IN_RANGE
            raise exc.FlowClassifierBadRequest(message=msg)

        # Destination ports range - up to 15 ports.
        dport_min = flow_classifier['destination_port_range_min']
        dport_max = flow_classifier['destination_port_range_max']
        if (dport_min is not None and dport_max is not None and
            (dport_max + 1 - dport_min) > MAX_PORTS_IN_RANGE):
            msg = _('The NSXv driver does not support setting '
                    'more than %d destination ports in a '
                    'FlowClassifier') % MAX_PORTS_IN_RANGE
            raise exc.FlowClassifierBadRequest(message=msg)
