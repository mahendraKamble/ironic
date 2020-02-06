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

"""
DRAC inspection interface
"""

import xml.etree.ElementTree as et

from ironic_lib import metrics_utils
from oslo_log import log as logging
from oslo_utils import importutils
from oslo_utils import units

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import states
from ironic.common import utils
from ironic.drivers import base
from ironic.drivers.modules.drac import common as drac_common
from ironic.drivers.modules.redfish import inspect as redfish_inspect
from ironic.drivers.modules.redfish import utils as redfish_utils
from ironic import objects

drac_exceptions = importutils.try_import('dracclient.exceptions')
sushy = importutils.try_import('sushy')

LOG = logging.getLogger(__name__)

METRICS = metrics_utils.get_metrics_logger(__name__)

# System Configuration Tag Constant
_SYSTEM_CONFIG_TAG = '<SystemConfiguration Model'

# System Management Constant
_SERVICE_ROOT = '/redfish/v1/Managers/'

# Job Response Code Constant
_JOB_RESPONSE_CODE = 200


class DracRedfishInspect(redfish_inspect.RedfishInspect):
    """iDRAC Redfish interface for inspection-related actions."""

    def inspect_hardware(self, task):
        """Inspect hardware to get the hardware properties.

        Inspects hardware to get the essential properties.
        It fails if any of the essential properties
        are not received from the node.

        :param task: a TaskManager instance.
        :raises: HardwareInspectionFailure if essential properties
                 could not be retrieved successfully.
        :returns: The resulting state of inspection.

        """
        super(DracRedfishInspect, self).inspect_hardware(task)

        node = task.node
        pxe_port_macs = self._get_pxe_port_macs(task)
        if pxe_port_macs is None:
            LOG.warning("No PXE enabled NIC was found for node "
                        "%(node_uuid)s.", {'node_uuid': node.uuid})
            ports = objects.Port.list_by_node_id(task.context, node.id)
            if ports:
                for port in ports:
                    if port.pxe_enabled:
                        port.pxe_enabled = False
                        port.save()
            return states.MANAGEABLE

        ports = objects.Port.list_by_node_id(task.context, node.id)
        if ports:
            for port in ports:
                is_pxe_port_mac = (port.address.upper() in pxe_port_macs)
                if port.pxe_enabled != is_pxe_port_mac:
                    port.pxe_enabled = is_pxe_port_mac
                    port.save()
                    LOG.info('Port %(port)s having %(mac_address)s updated '
                             'with pxe_enabled %(pxe)s for node %(node_uuid)s '
                             'during inspection',
                             {'port': port.uuid, 'mac_address': port.address,
                              'pxe': port.pxe_enabled, 'node_uuid': node.uuid})
        else:
            LOG.warning("No port information discovered "
                        "for node %(node)s", {'node': node.uuid})

        return states.MANAGEABLE

    def _get_pxe_port_macs(self, task):
        """Get a list of pxe port MAC addresses.

        :param task: a TaskManager instance.
        :returns: Returns list of pxe port MAC addresses.
        """
        system = redfish_utils.get_system(task.node)

        pxe_port_macs = []
        pxe_params = ["PxeDev1EnDis", "PxeDev2EnDis",
                      "PxeDev3EnDis", "PxeDev4EnDis"]
        pxe_nics = ["PxeDev1Interface", "PxeDev2Interface",
                    "PxeDev3Interface", "PxeDev4Interface"]

        redfish_ip = task.node.driver_info.get('redfish_address')
        redfish_username = task.node.driver_info.get('redfish_username')
        redfish_password = task.node.driver_info.get('redfish_password')

        # Get dictionary of ethernet interfaces
        ethernet_interfaces = system.ethernet_interfaces.get_members()
        ethernet_interfaces_mac_dict = {interface.identity: interface.mac_address for interface in ethernet_interfaces}

        if system.boot.mode == 'uefi':
            for param, nic in zip(pxe_params, pxe_nics):
                if system.bios.attributes[param] == 'Enabled':
                    nic_id = system.bios.attributes[nic]
                    # Get MAC address of the given nic_id
                    mac_address = ethernet_interfaces_mac_dict[nic_id]
                    pxe_port_macs.append(mac_address)
        elif system.boot.mode == 'bios':
            # Get instance of OEM extension
            authenticator = sushy.auth.BasicAuth(redfish_username, redfish_password)
            url = '%s%s' % (redfish_ip, _SERVICE_ROOT)
            conn = sushy.Sushy(url, verify=False, auth=authenticator)
            manager = conn.get_manager('iDRAC.Embedded.1')
            oem_manager = manager.get_oem_extension('Dell')
            job_response = oem_manager.export_system_configuration(target="NIC")

            if job_response.status_code != _JOB_RESPONSE_CODE:
                error = (_('An error occurred when attempting to export '
                           'the system configuration. Status code: %(code), '
                           'Error details: %(err)'),
                         {'code': job_response.status_code,
                          'err': job_response.__dict__})
                LOG.error(error)
                raise exception.HardwareInspectionFailure(error=error)

            if _SYSTEM_CONFIG_TAG in str(job_response.__dict__):
                xml_string = job_response.__dict__.get('_content')
                root = et.fromstring(xml_string)
                for child in root:
                    nic_id = [child.attrib.get('FQDD') for ch in child if
                              ch.text == 'PXE']
                    if nic_id:
                        # Get MAC address of the given nic_id
                        mac_address = ethernet_interfaces_mac_dict[nic_id[0]]
                        pxe_port_macs.append(mac_address)
                return pxe_port_macs
            else:
                error = (_('Failed to get system configuration from response'))
                raise exception.HardwareInspectionFailure(error=error)
        return pxe_port_macs


class DracWSManInspect(base.InspectInterface):

    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """
        return drac_common.COMMON_PROPERTIES

    @METRICS.timer('DracInspect.validate')
    def validate(self, task):
        """Validate the driver-specific info supplied.

        This method validates whether the 'driver_info' property of the
        supplied node contains the required information for this driver to
        manage the node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue if required driver_info attribute
                 is missing or invalid on the node.

        """
        return drac_common.parse_driver_info(task.node)

    @METRICS.timer('DracInspect.inspect_hardware')
    def inspect_hardware(self, task):
        """Inspect hardware.

        Inspect hardware to obtain the essential & additional hardware
        properties.

        :param task: a TaskManager instance containing the node to act on.
        :raises: HardwareInspectionFailure, if unable to get essential
                 hardware properties.
        :returns: states.MANAGEABLE
        """

        node = task.node
        client = drac_common.get_drac_client(node)
        properties = {}

        try:
            properties['memory_mb'] = sum(
                [memory.size_mb for memory in client.list_memory()])
            cpus = client.list_cpus()
            if cpus:
                properties['cpus'] = sum(
                    [self._calculate_cpus(cpu) for cpu in cpus])
                properties['cpu_arch'] = 'x86_64' if cpus[0].arch64 else 'x86'

            bios_settings = client.list_bios_settings()
            current_capabilities = node.properties.get('capabilities', '')
            new_capabilities = {
                'boot_mode': bios_settings["BootMode"].current_value.lower()}
            capabilties = utils.get_updated_capabilities(current_capabilities,
                                                         new_capabilities)
            properties['capabilities'] = capabilties

            virtual_disks = client.list_virtual_disks()
            root_disk = self._guess_root_disk(virtual_disks)
            if root_disk:
                properties['local_gb'] = int(root_disk.size_mb / units.Ki)
            else:
                physical_disks = client.list_physical_disks()
                root_disk = self._guess_root_disk(physical_disks)
                if root_disk:
                    properties['local_gb'] = int(
                        root_disk.size_mb / units.Ki)
        except drac_exceptions.BaseClientException as exc:
            LOG.error('DRAC driver failed to introspect node '
                      '%(node_uuid)s. Reason: %(error)s.',
                      {'node_uuid': node.uuid, 'error': exc})
            raise exception.HardwareInspectionFailure(error=exc)

        valid_keys = self.ESSENTIAL_PROPERTIES
        missing_keys = valid_keys - set(properties)
        if missing_keys:
            error = (_('Failed to discover the following properties: '
                       '%(missing_keys)s') %
                     {'missing_keys': ', '.join(missing_keys)})
            raise exception.HardwareInspectionFailure(error=error)

        node.properties = dict(node.properties, **properties)
        node.save()

        try:
            nics = client.list_nics()
        except drac_exceptions.BaseClientException as exc:
            LOG.error('DRAC driver failed to introspect node '
                      '%(node_uuid)s. Reason: %(error)s.',
                      {'node_uuid': node.uuid, 'error': exc})
            raise exception.HardwareInspectionFailure(error=exc)

        pxe_dev_nics = self._get_pxe_dev_nics(client, nics, node)
        if pxe_dev_nics is None:
            LOG.warning('No PXE enabled NIC was found for node '
                        '%(node_uuid)s.', {'node_uuid': node.uuid})

        for nic in nics:
            try:
                port = objects.Port(task.context, address=nic.mac,
                                    node_id=node.id,
                                    pxe_enabled=(nic.id in pxe_dev_nics))
                port.create()

                LOG.info('Port created with MAC address %(mac)s '
                         'for node %(node_uuid)s during inspection',
                         {'mac': nic.mac, 'node_uuid': node.uuid})
            except exception.MACAlreadyExists:
                LOG.warning('Failed to create a port with MAC address '
                            '%(mac)s when inspecting the node '
                            '%(node_uuid)s because the address is already '
                            'registered',
                            {'mac': nic.mac, 'node_uuid': node.uuid})

        LOG.info('Node %s successfully inspected.', node.uuid)
        return states.MANAGEABLE

    def _guess_root_disk(self, disks, min_size_required_mb=4 * units.Ki):
        """Find a root disk.

        :param disks: list of disks.
        :param min_size_required_mb: minimum required size of the root disk in
                                     megabytes.
        :returns: root disk.
        """
        disks.sort(key=lambda disk: disk.size_mb)
        for disk in disks:
            if disk.size_mb >= min_size_required_mb:
                return disk

    def _calculate_cpus(self, cpu):
        """Find actual CPU count.

        :param cpu: Pass cpu.

        :returns: returns total cpu count.
        """
        if cpu.ht_enabled:
            return cpu.cores * 2
        else:
            return cpu.cores

    def _get_pxe_dev_nics(self, client, nics, node):
        """Get a list of pxe device interfaces.

        :param client: Dracclient to list the bios settings and nics
        :param nics: list of nics

        :returns: Returns list of pxe device interfaces.
        """
        pxe_dev_nics = []
        pxe_params = ["PxeDev1EnDis", "PxeDev2EnDis",
                      "PxeDev3EnDis", "PxeDev4EnDis"]
        pxe_nics = ["PxeDev1Interface", "PxeDev2Interface",
                    "PxeDev3Interface", "PxeDev4Interface"]

        try:
            bios_settings = client.list_bios_settings()
        except drac_exceptions.BaseClientException as exc:
            LOG.error('DRAC driver failed to list bios settings '
                      'for %(node_uuid)s. Reason: %(error)s.',
                      {'node_uuid': node.uuid, 'error': exc})
            raise exception.HardwareInspectionFailure(error=exc)

        if bios_settings["BootMode"].current_value == "Uefi":
            for param, nic in zip(pxe_params, pxe_nics):
                if param in bios_settings and bios_settings[
                        param].current_value == "Enabled":
                    pxe_dev_nics.append(
                        bios_settings[nic].current_value)
        elif bios_settings["BootMode"].current_value == "Bios":
            for nic in nics:
                try:
                    nic_cap = client.list_nic_settings(nic_id=nic.id)
                except drac_exceptions.BaseClientException as exc:
                    LOG.error('DRAC driver failed to list nic settings '
                              'for %(node_uuid)s. Reason: %(error)s.',
                              {'node_uuid': node.uuid, 'error': exc})
                    raise exception.HardwareInspectionFailure(error=exc)

                if ("LegacyBootProto" in nic_cap and nic_cap[
                        'LegacyBootProto'].current_value == "PXE"):
                    pxe_dev_nics.append(nic.id)

        return pxe_dev_nics


class DracInspect(DracWSManInspect):
    """Class alias of class DracWSManInspect.

    This class provides ongoing support of the deprecated 'idrac'
    inspect interface implementation entrypoint.

    All bug fixes and new features should be implemented in its base
    class, DracWSManInspect. That makes them available to both the
    deprecated 'idrac' and new 'idrac-wsman' entrypoints. Such changes
    should not be made to this class.
    """

    def __init__(self):
        LOG.warning("Inspect interface 'idrac' is deprecated and may be "
                    "removed in a future release. Use 'idrac-wsman' instead.")
