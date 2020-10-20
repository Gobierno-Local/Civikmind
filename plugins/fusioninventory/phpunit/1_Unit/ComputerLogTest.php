<?php

/*
   ------------------------------------------------------------------------
   FusionInventory
   Copyright (C) 2010-2016 by the FusionInventory Development Team.

   http://www.fusioninventory.org/   http://forge.fusioninventory.org/
   ------------------------------------------------------------------------

   LICENSE

   This file is part of FusionInventory project.

   FusionInventory is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   FusionInventory is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with FusionInventory. If not, see <http://www.gnu.org/licenses/>.

   ------------------------------------------------------------------------

   @package   FusionInventory
   @author    David Durieux
   @co-author
   @copyright Copyright (c) 2010-2016 FusionInventory team
   @license   AGPL License 3.0 or (at your option) any later version
              http://www.gnu.org/licenses/agpl-3.0-standalone.html
   @link      http://www.fusioninventory.org/
   @link      http://forge.fusioninventory.org/projects/fusioninventory-for-glpi/
   @since     2013

   ------------------------------------------------------------------------
 */

class ComputerLog extends RestoreDatabase_TestCase {

   private $a_inventory = [];


   public function testLog() {
      global $DB;

      $DB->connect();

      $pfFormatconvert  = new PluginFusioninventoryFormatconvert();
      $computer         = new Computer();
      $pfiComputerLib   = new PluginFusioninventoryInventoryComputerLib();

      $date = date('Y-m-d H:i:s');

      $_SESSION["plugin_fusioninventory_entity"] = 0;
      $_SESSION['glpiactiveentities_string'] = 0;
      $_SESSION['glpishowallentities'] = 1;
      $_SESSION["glpiname"] = 'Plugin_FusionInventory';

      $this->a_inventory = [
          'fusioninventorycomputer' => [
              'winowner'                        => 'test',
              'wincompany'                      => 'siprossii',
              'operatingsystem_installationdate'=> '2012-10-16 08:12:56',
              'last_fusioninventory_update'     => $date,
              'last_boot'                       => '2018-06-11 08:03:32',
          ],
          'soundcard'      => [],
          'graphiccard'    => [],
          'controller'     => [],
          'processor'      => [],
          'computerdisk'   => [],
          'memory'         => [],
          'monitor'        => [],
          'printer'        => [],
          'peripheral'     => [],
          'networkport'    => [],
          'SOFTWARES'      => [],
          'harddrive'      => [],
          'virtualmachine' => [],
          'antivirus'      => [],
          'storage'        => [],
          'licenseinfo'    => [],
          'networkcard'    => [],
          'drive'          => [],
          'batteries'      => [],
          'remote_mgmt'    => [],
          'bios'           => [],
          'itemtype'       => 'Computer'
          ];
      $this->a_inventory['Computer'] = [
          'name'                             => 'pc',
          'users_id'                         => 0,
          'operatingsystems_id'              => 'freebsd',
          'operatingsystemversions_id'       => '9.1-RELEASE',
          'uuid'                             => '68405E00-E5BE-11DF-801C-B05981201220',
          'domains_id'                       => 'mydomain.local',
          'os_licenseid'                     => '',
          'os_license_number'                => '',
          'operatingsystemservicepacks_id'   => 'GENERIC ()root@farrell.cse.buffalo.edu',
          'manufacturers_id'                 => '',
          'computermodels_id'                => '',
          'serial'                           => 'XB63J7D',
          'computertypes_id'                 => 'Notebook',
          'is_dynamic'                       => 1,
          'contact'                          => 'ddurieux'
      ];

      $this->a_inventory['processor'] = [
            [
                    'nbcores'           => 2,
                    'manufacturers_id'  => 'Intel Corporation',
                    'designation'       => 'Core i3',
                    'frequence'         => 2400,
                    'nbthreads'         => 2,
                    'serial'            => '',
                    'frequency'         => 2400,
                    'frequency_default' => 2400
                ],
            [
                    'nbcores'           => 2,
                    'manufacturers_id'  => 'Intel Corporation',
                    'designation'       => 'Core i3',
                    'frequence'         => 2400,
                    'nbthreads'         => 2,
                    'serial'            => '',
                    'frequency'         => 2400,
                    'frequency_default' => 2400
                ],
            [
                    'nbcores'           => 2,
                    'manufacturers_id'  => 'Intel Corporation',
                    'designation'       => 'Core i3',
                    'frequence'         => 2400,
                    'nbthreads'         => 2,
                    'serial'            => '',
                    'frequency'         => 2400,
                    'frequency_default' => 2400
                ],
            [
                    'nbcores'           => 2,
                    'manufacturers_id'  => 'Intel Corporation',
                    'designation'       => 'Core i3',
                    'frequence'         => 2400,
                    'nbthreads'         => 2,
                    'serial'            => '',
                    'frequency'         => 2400,
                    'frequency_default' => 2400
                ]
        ];

      $this->a_inventory['memory'] = [
            [
                    'size'                 => 2048,
                    'serial'               => '98F6FF18',
                    'frequence'            => '1067',
                    'devicememorytypes_id' => 'DDR3',
                    'designation'          => 'DDR3 - SODIMM (None)',
                    'busID'                => 1
                ],
            [
                    'size'                 => 2048,
                    'serial'               => '95F1833E',
                    'frequence'            => '1067',
                    'devicememorytypes_id' => 'DDR3',
                    'designation'          => 'DDR3 - SODIMM (None)',
                    'busID'                => 2
                ]
        ];

      $this->a_inventory['monitor'] = [
            [
                    'name'              => '',
                    'serial'            => '',
                    'manufacturers_id'  => ''
                ]
      ];

      $this->a_inventory['networkport'] = [
            'em0-00:23:18:cf:0d:93' => [
                    'name'                 => 'em0',
                    'netmask'              => '255.255.255.0',
                    'subnet'               => '192.168.30.0',
                    'mac'                  => '00:23:18:cf:0d:93',
                    'instantiation_type'   => 'NetworkPortEthernet',
                    'virtualdev'           => 0,
                    'ssid'                 => '',
                    'gateway'              => '',
                    'dhcpserver'           => '',
                    'logical_number'       => 0,
                    'ipaddress'            => ['192.168.30.198']
                ],
            'lo0-' => [
                    'name'                 => 'lo0',
                    'virtualdev'           => 1,
                    'mac'                  => '',
                    'instantiation_type'   => 'NetworkPortLocal',
                    'subnet'               => '',
                    'ssid'                 => '',
                    'gateway'              => '',
                    'netmask'              => '',
                    'dhcpserver'           => '',
                    'logical_number'       => 1,
                    'ipaddress'            => ['::1', 'fe80::1', '127.0.0.1']
                ]
        ];

      $this->a_inventory['software'] = [
            'gentiumbasic$$$$110$$$$1$$$$0$$$$0' => [
                    'name'                   => 'GentiumBasic',
                    'version'                => 110,
                    'manufacturers_id'       => 1,
                    'entities_id'            => 0,
                    'is_template_item'   => 0,
                    'is_deleted_item'    => 0,
                    'is_dynamic'             => 1,
                    'operatingsystems_id'    => 0
                ],
            'imagemagick$$$$6.8.0.7_1$$$$2$$$$0$$$$0' => [
                    'name'                   => 'ImageMagick',
                    'version'                => '6.8.0.7_1',
                    'manufacturers_id'       => 2,
                    'entities_id'            => 0,
                    'is_template_item'   => 0,
                    'is_deleted_item'    => 0,
                    'is_dynamic'             => 1,
                    'operatingsystems_id'    => 0
                ],
            'orbit2$$$$2.14.19$$$$3$$$$0$$$$0' => [
                    'name'                   => 'ORBit2',
                    'version'                => '2.14.19',
                    'manufacturers_id'       => 3,
                    'entities_id'            => 0,
                    'is_template_item'   => 0,
                    'is_deleted_item'    => 0,
                    'is_dynamic'             => 1,
                    'operatingsystems_id'    => 0
                ]
          ];

      $this->a_inventory = $pfFormatconvert->replaceids($this->a_inventory, 'Computer', 0);

      $serialized = gzcompress(serialize($this->a_inventory));
      $this->a_inventory['fusioninventorycomputer']['serialized_inventory'] =
               Toolbox::addslashes_deep($serialized);

      $computer->add(['serial' => 'XB63J7D',
                           'entities_id' => 0]);

      // truncate glpi_logs
      $DB->query('TRUNCATE TABLE `glpi_logs`;');

      $this->assertEquals(0, countElementsInTable('glpi_logs'), "Log must be empty (truncate)");

      $_SESSION['glpiactive_entity'] = 0;
      $pfiComputerLib->updateComputer($this->a_inventory, 1, true);

      $a_logs = getAllDataFromTable('glpi_logs');
      foreach ($a_logs as $id=>$data) {
         unset($data['date_mod']);
         unset($data['date_creation']);
         $a_logs[$id] = $data;
      }

      $a_reference = [
          1 => [
              'id'               => '1',
              'itemtype'         => 'DeviceProcessor',
              'items_id'         => '1',
              'itemtype_link'    => '0',
              'linked_action'    => '20',
              'user_name'        => '',
              'id_search_option' => '0',
              'old_value'        => '',
              'new_value'        => ''
              ],
          2 => [
              'id'               => '2',
              'itemtype'         => 'DeviceMemory',
              'items_id'         => '1',
              'itemtype_link'    => '0',
              'linked_action'    => '20',
              'user_name'        => '',
              'id_search_option' => '0',
              'old_value'        => '',
              'new_value'        => ''
              ],
          3 => [
              'id'               => '3',
              'itemtype'         => 'Software',
              'items_id'         => '1',
              'itemtype_link'    => '',
              'linked_action'    => '20',
              'user_name'        => 'Plugin_FusionInventory',
              'id_search_option' => '0',
              'old_value'        => '',
              'new_value'        => ''
              ],
          4 => [
              'id'               => '4',
              'itemtype'         => 'Software',
              'items_id'         => '2',
              'itemtype_link'    => '',
              'linked_action'    => '20',
              'user_name'        => 'Plugin_FusionInventory',
              'id_search_option' => '0',
              'old_value'        => '',
              'new_value'        => ''
              ],
          5 => [
              'id'               => '5',
              'itemtype'         => 'Software',
              'items_id'         => '3',
              'itemtype_link'    => '',
              'linked_action'    => '20',
              'user_name'        => 'Plugin_FusionInventory',
              'id_search_option' => '0',
              'old_value'        => '',
              'new_value'        => ''
              ],
          6 => [
              'id'               => '6',
              'itemtype'         => 'SoftwareVersion',
              'items_id'         => '1',
              'itemtype_link'    => '',
              'linked_action'    => '20',
              'user_name'        => 'Plugin_FusionInventory',
              'id_search_option' => '0',
              'old_value'        => '',
              'new_value'        => ''
              ],
          7 => [
              'id'               => '7',
              'itemtype'         => 'SoftwareVersion',
              'items_id'         => '2',
              'itemtype_link'    => '',
              'linked_action'    => '20',
              'user_name'        => 'Plugin_FusionInventory',
              'id_search_option' => '0',
              'old_value'        => '',
              'new_value'        => ''
              ],
          8 => [
              'id'               => '8',
              'itemtype'         => 'SoftwareVersion',
              'items_id'         => '3',
              'itemtype_link'    => '',
              'linked_action'    => '20',
              'user_name'        => 'Plugin_FusionInventory',
              'id_search_option' => '0',
              'old_value'        => '',
              'new_value'        => ''
              ],
      ];

      $this->assertEquals($a_reference, $a_logs, "Log must be 8 ".print_r($a_logs, true));
      $DB->query('TRUNCATE `glpi_logs`');

      // Update a second time and must not have any new lines in glpi_logs
      $pfiComputerLib->updateComputer($this->a_inventory, 1, false);

      $a_logs = getAllDataFromTable('glpi_logs');
      $a_reference = [];

      $this->assertEquals($a_reference, $a_logs, "Log may be empty at second update ".print_r($a_logs, true));

      // * Modify: contact
      // * remove a processor
      // * Remove a software
      $this->a_inventory['Computer']['contact'] = 'root';
      unset($this->a_inventory['processor'][3]);
      unset($this->a_inventory['software']['orbit2$$$$2.14.19$$$$3$$$$0$$$$0']);

      $DB->query('TRUNCATE `glpi_logs`');
      $pfiComputerLib->updateComputer($this->a_inventory, 1, false);

      $a_logs = getAllDataFromTable('glpi_logs');
      foreach ($a_logs as $id=>$data) {
         unset($data['date_mod']);
         unset($data['date_creation']);
         $a_logs[$id] = $data;
      }
      $a_reference = [
          1 => [
              'id'               => '1',
              'itemtype'         => 'Computer',
              'items_id'         => '1',
              'itemtype_link'    => '',
              'linked_action'    => '0',
              'user_name'        => '',
              'id_search_option' => '7',
              'old_value'        => 'ddurieux',
              'new_value'        => 'root'
          ],
          2 => [
              'id'               => '2',
              'itemtype'         => 'Computer',
              'items_id'         => '1',
              'itemtype_link'    => 'DeviceProcessor',
              'linked_action'    => '3',
              'user_name'        => '',
              'id_search_option' => '0',
              'old_value'        => 'Core i3 (1)',
              'new_value'        => ''
          ],
          3 => [
              'id'               => '3',
              'itemtype'         => 'Computer',
              'items_id'         => '1',
              'itemtype_link'    => 'SoftwareVersion',
              'linked_action'    => '5',
              'user_name'        => 'Plugin_FusionInventory',
              'id_search_option' => '0',
              'old_value'        => 'ORBit2 - 2.14.19 (3)',
              'new_value'        => ''
          ],
          4 => [
              'id'               => '4',
              'itemtype'         => 'SoftwareVersion',
              'items_id'         => '3',
              'itemtype_link'    => 'Computer',
              'linked_action'    => '5',
              'user_name'        => 'Plugin_FusionInventory',
              'id_search_option' => '0',
              'old_value'        => 'pc (1)',
              'new_value'        => ''
          ]
      ];

      $this->assertEquals($a_reference, $a_logs, "May have 5 logs (update contact, remove processor
         and remove a software)");

   }


}




