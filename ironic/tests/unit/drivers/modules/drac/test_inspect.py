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
Test class for DRAC inspection interface
"""

from dracclient import exceptions as drac_exceptions
import mock
from oslo_utils import importutils
from oslo_utils import units

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers.modules.drac import common as drac_common
from ironic.drivers.modules.drac import inspect as drac_inspect
from ironic.drivers.modules.drac.inspect import DracRedfishInspect
from ironic.drivers.modules.redfish import utils as redfish_utils
from ironic import objects
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.drivers.modules.drac import utils as test_utils
from ironic.tests.unit.objects import utils as obj_utils

sushy = importutils.try_import('sushy')

INFO_DICT = test_utils.INFO_DICT

DRAC_REDFISH_INFO_DICT = db_utils.get_test_redfish_info()

# System Management Constant
_SERVICE_ROOT = '/redfish/v1/Managers/'

authenticator = sushy.auth.BasicAuth(DRAC_REDFISH_INFO_DICT["redfish_username"], DRAC_REDFISH_INFO_DICT["redfish_password"])
url = '%s%s' % (DRAC_REDFISH_INFO_DICT["redfish_address"], _SERVICE_ROOT)
conn = sushy.Sushy(url, verify=False, auth=authenticator)
manager = conn.get_manager('iDRAC.Embedded.1')
oem_manager = manager.get_oem_extension('Dell')

class DracInspectionTestCase(test_utils.BaseDracTest):

    def setUp(self):
        super(DracInspectionTestCase, self).setUp()
        self.node = obj_utils.create_test_node(self.context,
                                               driver='idrac',
                                               driver_info=INFO_DICT)
        memory = [{'id': 'DIMM.Socket.A1',
                   'size_mb': 16384,
                   'speed': 2133,
                   'manufacturer': 'Samsung',
                   'model': 'DDR4 DIMM',
                   'state': 'ok'},
                  {'id': 'DIMM.Socket.B1',
                   'size_mb': 16384,
                   'speed': 2133,
                   'manufacturer': 'Samsung',
                   'model': 'DDR4 DIMM',
                   'state': 'ok'}]
        cpus = [{'id': 'CPU.Socket.1',
                 'cores': 6,
                 'speed': 2400,
                 'model': 'Intel(R) Xeon(R) CPU E5-2620 v3 @ 2.40GHz',
                 'state': 'ok',
                 'ht_enabled': True,
                 'turbo_enabled': True,
                 'vt_enabled': True,
                 'arch64': True},
                {'id': 'CPU.Socket.2',
                 'cores': 6,
                 'speed': 2400,
                 'model': 'Intel(R) Xeon(R) CPU E5-2620 v3 @ 2.40GHz',
                 'state': 'ok',
                 'ht_enabled': False,
                 'turbo_enabled': True,
                 'vt_enabled': True,
                 'arch64': True}]
        virtual_disks = [
            {'id': 'Disk.Virtual.0:RAID.Integrated.1-1',
             'name': 'disk 0',
             'description': 'Virtual Disk 0 on Integrated RAID Controller 1',
             'controller': 'RAID.Integrated.1-1',
             'raid_level': '1',
             'size_mb': 1143552,
             'state': 'ok',
             'raid_state': 'online',
             'span_depth': 1,
             'span_length': 2,
             'pending_operations': None}]
        physical_disks = [
            {'id': 'Disk.Bay.1:Enclosure.Internal.0-1:RAID.Integrated.1-1',
             'description': ('Disk 1 in Backplane 1 of '
                             'Integrated RAID Controller 1'),
             'controller': 'RAID.Integrated.1-1',
             'manufacturer': 'SEAGATE',
             'model': 'ST600MM0006',
             'media_type': 'hdd',
             'interface_type': 'sas',
             'size_mb': 571776,
             'free_size_mb': 571776,
             'serial_number': 'S0M3EY2Z',
             'firmware_version': 'LS0A',
             'state': 'ok',
             'raid_state': 'ready'},
            {'id': 'Disk.Bay.2:Enclosure.Internal.0-1:RAID.Integrated.1-1',
             'description': ('Disk 1 in Backplane 1 of '
                             'Integrated RAID Controller 1'),
             'controller': 'RAID.Integrated.1-1',
             'manufacturer': 'SEAGATE',
             'model': 'ST600MM0006',
             'media_type': 'hdd',
             'interface_type': 'sas',
             'size_mb': 285888,
             'free_size_mb': 285888,
             'serial_number': 'S0M3EY2Z',
             'firmware_version': 'LS0A',
             'state': 'ok',
             'raid_state': 'ready'}]
        nics = [
            {'id': 'NIC.Embedded.1-1-1',
             'mac': 'B0:83:FE:C6:6F:A1',
             'model': 'Broadcom Gigabit Ethernet BCM5720 - B0:83:FE:C6:6F:A1',
             'speed': '1000 Mbps',
             'duplex': 'full duplex',
             'media_type': 'Base T'},
            {'id': 'NIC.Embedded.2-1-1',
             'mac': 'B0:83:FE:C6:6F:A2',
             'model': 'Broadcom Gigabit Ethernet BCM5720 - B0:83:FE:C6:6F:A2',
             'speed': '1000 Mbps',
             'duplex': 'full duplex',
             'media_type': 'Base T'}]
        bios_boot_settings = {'BootMode': {'current_value': 'Bios'}}
        uefi_boot_settings = {'BootMode': {'current_value': 'Uefi'},
                              'PxeDev1EnDis': {'current_value': 'Enabled'},
                              'PxeDev2EnDis': {'current_value': 'Disabled'},
                              'PxeDev3EnDis': {'current_value': 'Disabled'},
                              'PxeDev4EnDis': {'current_value': 'Disabled'},
                              'PxeDev1Interface': {
                                  'current_value': 'NIC.Embedded.1-1-1'},
                              'PxeDev2Interface': None,
                              'PxeDev3Interface': None,
                              'PxeDev4Interface': None}
        nic_settings = {'LegacyBootProto': {'current_value': 'PXE'},
                        'FQDD': 'NIC.Embedded.1-1-1'}

        self.memory = [test_utils.dict_to_namedtuple(values=m) for m in memory]
        self.cpus = [test_utils.dict_to_namedtuple(values=c) for c in cpus]
        self.virtual_disks = [test_utils.dict_to_namedtuple(values=vd)
                              for vd in virtual_disks]
        self.physical_disks = [test_utils.dict_to_namedtuple(values=pd)
                               for pd in physical_disks]
        self.nics = [test_utils.dict_to_namedtuple(values=n) for n in nics]
        self.bios_boot_settings = test_utils.dict_of_object(bios_boot_settings)
        self.uefi_boot_settings = test_utils.dict_of_object(uefi_boot_settings)
        self.nic_settings = test_utils.dict_of_object(nic_settings)

    def test_get_properties(self):
        expected = drac_common.COMMON_PROPERTIES
        driver = drac_inspect.DracInspect()
        self.assertEqual(expected, driver.get_properties())

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(objects.Port, 'create', spec_set=True, autospec=True)
    def test_inspect_hardware(self, mock_port_create, mock_get_drac_client):
        expected_node_properties = {
            'memory_mb': 32768,
            'local_gb': 1116,
            'cpus': 18,
            'cpu_arch': 'x86_64',
            'capabilities': 'boot_mode:uefi'}
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_memory.return_value = self.memory
        mock_client.list_cpus.return_value = self.cpus
        mock_client.list_virtual_disks.return_value = self.virtual_disks
        mock_client.list_nics.return_value = self.nics
        mock_client.list_bios_settings.return_value = self.uefi_boot_settings

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            return_value = task.driver.inspect.inspect_hardware(task)

        self.node.refresh()
        self.assertEqual(expected_node_properties, self.node.properties)
        self.assertEqual(states.MANAGEABLE, return_value)
        self.assertEqual(2, mock_port_create.call_count)

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(objects.Port, 'create', spec_set=True, autospec=True)
    def test_inspect_hardware_fail(self, mock_port_create,
                                   mock_get_drac_client):
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_memory.return_value = self.memory
        mock_client.list_cpus.return_value = self.cpus
        mock_client.list_virtual_disks.side_effect = (
            drac_exceptions.BaseClientException('boom'))
        mock_client.list_bios_settings.return_value = self.bios_boot_settings

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.HardwareInspectionFailure,
                              task.driver.inspect.inspect_hardware, task)

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(objects.Port, 'create', spec_set=True, autospec=True)
    def test_inspect_hardware_no_virtual_disk(self, mock_port_create,
                                              mock_get_drac_client):
        expected_node_properties = {
            'memory_mb': 32768,
            'local_gb': 279,
            'cpus': 18,
            'cpu_arch': 'x86_64',
            'capabilities': 'boot_mode:uefi'}
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_memory.return_value = self.memory
        mock_client.list_cpus.return_value = self.cpus
        mock_client.list_virtual_disks.return_value = []
        mock_client.list_physical_disks.return_value = self.physical_disks
        mock_client.list_nics.return_value = self.nics
        mock_client.list_bios_settings.return_value = self.uefi_boot_settings

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            return_value = task.driver.inspect.inspect_hardware(task)

        self.node.refresh()
        self.assertEqual(expected_node_properties, self.node.properties)
        self.assertEqual(states.MANAGEABLE, return_value)
        self.assertEqual(2, mock_port_create.call_count)

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(objects.Port, 'create', spec_set=True, autospec=True)
    def test_inspect_hardware_no_cpu(
            self, mock_port_create, mock_get_drac_client):
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_memory.return_value = self.memory
        mock_client.list_cpus.return_value = []
        mock_client.list_virtual_disks.return_value = []
        mock_client.list_physical_disks.return_value = self.physical_disks
        mock_client.list_nics.return_value = self.nics
        mock_client.list_bios_settings.return_value = self.uefi_boot_settings

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.HardwareInspectionFailure,
                              task.driver.inspect.inspect_hardware, task)

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    @mock.patch.object(objects.Port, 'create', spec_set=True, autospec=True)
    def test_inspect_hardware_with_existing_ports(self, mock_port_create,
                                                  mock_get_drac_client):
        expected_node_properties = {
            'memory_mb': 32768,
            'local_gb': 1116,
            'cpus': 18,
            'cpu_arch': 'x86_64',
            'capabilities': 'boot_mode:uefi'}
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_memory.return_value = self.memory
        mock_client.list_cpus.return_value = self.cpus
        mock_client.list_virtual_disks.return_value = self.virtual_disks
        mock_client.list_nics.return_value = self.nics
        mock_client.list_bios_settings.return_value = self.uefi_boot_settings

        mock_port_create.side_effect = exception.MACAlreadyExists("boom")

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            return_value = task.driver.inspect.inspect_hardware(task)

        self.node.refresh()
        self.assertEqual(expected_node_properties, self.node.properties)
        self.assertEqual(states.MANAGEABLE, return_value)
        self.assertEqual(2, mock_port_create.call_count)

    def test__guess_root_disk(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            root_disk = task.driver.inspect._guess_root_disk(
                self.physical_disks)

            self.assertEqual(285888, root_disk.size_mb)

    def test__calculate_cpus(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            cpu = task.driver.inspect._calculate_cpus(
                self.cpus[0])

            self.assertEqual(12, cpu)

    def test__calculate_cpus_without_ht_enabled(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            cpu = task.driver.inspect._calculate_cpus(
                self.cpus[1])

            self.assertEqual(6, cpu)

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    def test__get_pxe_dev_nics_with_UEFI_boot_mode(self, mock_get_drac_client):
        expected_pxe_nic = self.uefi_boot_settings[
            'PxeDev1Interface'].current_value
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_bios_settings.return_value = self.uefi_boot_settings
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            pxe_dev_nics = task.driver.inspect._get_pxe_dev_nics(
                mock_client, self.nics, self.node)

            self.assertEqual(expected_pxe_nic, pxe_dev_nics[0])

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    def test__get_pxe_dev_nics_with_BIOS_boot_mode(self, mock_get_drac_client):
        expected_pxe_nic = self.nic_settings['FQDD']
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_bios_settings.return_value = self.bios_boot_settings
        mock_client.list_nic_settings.return_value = self.nic_settings
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            pxe_dev_nics = task.driver.inspect._get_pxe_dev_nics(
                mock_client, self.nics, self.node)

            self.assertEqual(expected_pxe_nic, pxe_dev_nics[0])

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    def test__get_pxe_dev_nics_list_boot_setting_failure(self,
                                                         mock_get_drac_client):
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_bios_settings.side_effect = (
            drac_exceptions.BaseClientException('foo'))

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.HardwareInspectionFailure,
                              task.driver.inspect._get_pxe_dev_nics,
                              mock_client,
                              self.nics,
                              self.node)

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    def test__get_pxe_dev_nics_list_nic_setting_failure(self,
                                                        mock_get_drac_client):
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_bios_settings.return_value = self.bios_boot_settings
        mock_client.list_nic_settings.side_effect = (
            drac_exceptions.BaseClientException('bar'))

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            self.assertRaises(exception.HardwareInspectionFailure,
                              task.driver.inspect._get_pxe_dev_nics,
                              mock_client,
                              self.nics,
                              self.node)

    @mock.patch.object(drac_common, 'get_drac_client', spec_set=True,
                       autospec=True)
    def test__get_pxe_dev_nics_with_empty_list(self, mock_get_drac_client):
        expected_pxe_nic = []
        nic_setting = []
        mock_client = mock.Mock()
        mock_get_drac_client.return_value = mock_client
        mock_client.list_bios_settings.return_value = self.bios_boot_settings
        mock_client.list_nic_settings.return_value = nic_setting
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            pxe_dev_nics = task.driver.inspect._get_pxe_dev_nics(
                mock_client, self.nics, self.node)

            self.assertEqual(expected_pxe_nic, pxe_dev_nics)


class DracRedfishInspectionTestCase(test_utils.BaseDracTest):
    def setUp(self):
        super(DracRedfishInspectionTestCase, self).setUp()
        self.config(enabled_hardware_types=['idrac'],
                    enabled_power_interfaces=['idrac-redfish'],
                    enabled_management_interfaces=['idrac-redfish'],
                    enabled_inspect_interfaces=['idrac-redfish'])
        self.node = obj_utils.create_test_node(
            self.context, driver='idrac',
            driver_info=DRAC_REDFISH_INFO_DICT)

    def init_system_mock(self, system_mock, **properties):
        system_mock.reset()
        system_mock.boot.mode = 'uefi'
        system_mock.bios.attributes = {
            'PxeDev1EnDis': 'Enabled', 'PxeDev2EnDis': 'Disabled',
            'PxeDev3EnDis': 'Disabled', 'PxeDev4EnDis': 'Disabled',
            'PxeDev1Interface': 'NIC.Integrated.1-1-1',
            'PxeDev2Interface': None, 'PxeDev3Interface': None,
            'PxeDev4Interface': None}

        system_mock.memory_summary.size_gib = 2

        system_mock.processors.summary = '8', 'MIPS'

        system_mock.simple_storage.disks_sizes_bytes = (
            1 * units.Gi, units.Gi * 3, units.Gi * 5)
        system_mock.storage.volumes_sizes_bytes = (
            2 * units.Gi, units.Gi * 4, units.Gi * 6)

        system_mock.ethernet_interfaces.summary = {
            '00:11:22:33:44:55': sushy.STATE_ENABLED,
            '66:77:88:99:AA:BB': sushy.STATE_DISABLED}
        member_data = [{
            'description': 'Integrated NIC 1 Port 1 Partition 1',
            'name': 'System Ethernet Interface',
            'full_duplex': False,
            'identity': 'NIC.Integrated.1-1-1',
            'mac_address': '24:6E:96:70:49:00',
            'mtu_size': None,
            'speed_mbps': 0,
            'vlan': None}]
        system_mock.ethernet_interfaces.get_members.return_value = [
            test_utils.dict_to_namedtuple(values=interface)
            for interface in member_data
        ]
        return system_mock

    def test_get_properties(self):
        expected = redfish_utils.COMMON_PROPERTIES
        driver = drac_inspect.DracRedfishInspect()
        self.assertEqual(expected, driver.get_properties())

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test__get_pxe_port_macs_with_UEFI_boot_mode(self, mock_get_system):
        system_mock = self.init_system_mock(mock_get_system.return_value)
        system_mock.boot.mode = 'uefi'
        expected_pxe_mac = ['24:6E:96:70:49:00']

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            pxe_port_macs = task.driver.inspect._get_pxe_port_macs(task)
            self.assertEqual(expected_pxe_mac, pxe_port_macs)

    @mock.patch.object(oem_manager, 'export_system_configuration', autospec=True)
    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test__get_pxe_port_macs_with_BIOS_boot_mode(self, mock_get_system,
            mock_export_system_configuration):
        system_mock = self.init_system_mock(mock_get_system.return_value)
        system_mock.boot.mode = 'bios'
        export_configuration = {
            '_content': '<SystemConfiguration Model="PowerEdge R640" '
                        'ServiceTag="DLMP4Z2" '
                        'TimeStamp="Thu Jan 23 09:27:07 2020">\n'
                        '<Component FQDD="NIC.Integrated.1-1-1">\n'
                        '<Attribute Name="LegacyBootProto">PXE</Attribute>\n'
                        '</Component>\n<Component FQDD="NIC.Integrated.1-2-1">\n'
                        '<Attribute Name="LegacyBootProto">NONE</Attribute>\n'
                        '</Component>\n </SystemConfiguration>',
            'status_code': 200
        }
        export_config = test_utils.DictToObj(export_configuration)
        expected_pxe_mac = ['24:6E:96:70:49:00']
        mock_export_system_configuration.return_value = export_config

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            pxe_port_macs = task.driver.inspect._get_pxe_port_macs(task)
            self.assertEqual(expected_pxe_mac, pxe_port_macs)

    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test__get_pxe_port_macs_without_boot_mode(self, mock_get_system):
        system_mock = self.init_system_mock(mock_get_system.return_value)
        system_mock.boot.mode = None
        expected_pxe_mac = []

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            pxe_port_macs = task.driver.inspect._get_pxe_port_macs(task)
            self.assertEqual(expected_pxe_mac, pxe_port_macs)

    @mock.patch.object(objects.Port, 'list_by_node_id', autospec=True)
    @mock.patch.object(DracRedfishInspect, '_get_pxe_port_macs', autospec=True)
    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_inspect_hardware_without_pxe_port_macs(
            self, mock_get_system, mock__get_pxe_port_macs,
            mock_list_by_node_id):
        self.init_system_mock(mock_get_system.return_value)
        mock__get_pxe_port_macs.return_value = None

        pxe_enabled_port = obj_utils.create_test_port(
            self.context, uuid=self.node.uuid,
            node_id=self.node.id, address='24:6E:96:70:49:01',
            pxe_enabled=True)
        mock_list_by_node_id.return_value = [pxe_enabled_port]

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            return_value = task.driver.inspect.inspect_hardware(task)
            port = mock_list_by_node_id.return_value
            self.assertFalse(port[0].pxe_enabled)
            self.assertEqual(states.MANAGEABLE, return_value)

    @mock.patch.object(objects.Port, 'list_by_node_id', autospec=True)
    @mock.patch.object(DracRedfishInspect, '_get_pxe_port_macs', autospec=True)
    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_inspect_hardware_with_set_port_pxe_enabled(
            self, mock_get_system, mock__get_pxe_port_macs,
            mock_list_by_node_id):
        self.init_system_mock(mock_get_system.return_value)
        mock__get_pxe_port_macs.return_value = ['24:6E:96:70:49:00']

        pxe_disabled_port = obj_utils.create_test_port(
            self.context, uuid=self.node.uuid, node_id=self.node.id,
            address='24:6E:96:70:49:00', pxe_enabled=False)
        mock_list_by_node_id.return_value = [pxe_disabled_port]

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.driver.inspect.inspect_hardware(task)

            port = mock_list_by_node_id.return_value
            self.assertTrue(port[0].pxe_enabled)

    @mock.patch.object(objects.Port, 'list_by_node_id', autospec=True)
    @mock.patch.object(DracRedfishInspect, '_get_pxe_port_macs', autospec=True)
    @mock.patch.object(redfish_utils, 'get_system', autospec=True)
    def test_inspect_hardware_with_set_port_pxe_disabled(
            self, mock_get_system, mock__get_pxe_port_macs,
            mock_list_by_node_id):
        self.init_system_mock(mock_get_system.return_value)
        mock__get_pxe_port_macs.return_value = ['24:6E:96:70:49:00']

        pxe_enabled_port = obj_utils.create_test_port(
            self.context, uuid=self.node.uuid,
            node_id=self.node.id, address='24:6E:96:70:49:01',
            pxe_enabled=True)
        mock_list_by_node_id.return_value = [pxe_enabled_port]

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=True) as task:
            task.driver.inspect.inspect_hardware(task)

            port = mock_list_by_node_id.return_value
            self.assertFalse(port[0].pxe_enabled)
