<?php
/*
 -------------------------------------------------------------------------
 credit plugin for GLPI
 Copyright (C) 2017 by the credit Development Team.

 https://github.com/pluginsGLPI/credit
 -------------------------------------------------------------------------

 LICENSE

 This file is part of credit.

 credit is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 credit is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with credit. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------
 */

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access this file directly");
}

class PluginCreditType extends CommonTreeDropdown {

   // From CommonDBTM
   public $dohistory          = true;
   public $can_be_translated  = true;

   static function getTypeName($nb=0) {
      return _n('Credit voucher type', 'Credit vouchers types', $nb, 'credit');
   }

   /**
    * Install all necessary table for the plugin
    *
    * @return boolean True if success
    */
   static function install(Migration $migration) {
      global $DB;

      $table = getTableForItemType(__CLASS__);

      if (!TableExists($table)) {
         $migration->displayMessage("Installing $table");

         $query = "CREATE TABLE IF NOT EXISTS `$table` (
                     `id` int(11) NOT NULL auto_increment,
                     `entities_id` int(11) NOT NULL DEFAULT '0',
                     `is_recursive` tinyint(1) NOT NULL DEFAULT '0',
                     `name` varchar(255) NOT NULL DEFAULT '',
                     `comment` text collate utf8_unicode_ci,
                     `completename` VARCHAR(255) NULL DEFAULT NULL,
                     `plugin_credit_types_id` INT(11) NOT NULL DEFAULT '0',
                     `level` INT(11) NOT NULL DEFAULT '1',
                     `sons_cache` LONGTEXT NULL COLLATE 'utf8_unicode_ci',
                     `ancestors_cache` LONGTEXT NULL COLLATE 'utf8_unicode_ci',
                     `date_mod` datetime DEFAULT NULL,
                     `date_creation` datetime DEFAULT NULL,
                     PRIMARY KEY (`id`),
                     UNIQUE KEY `unicity` (`entities_id`,`plugin_credit_types_id`,`name`),
                     KEY `plugin_credit_types_id` (`plugin_credit_types_id`),
                     KEY `name` (`name`),
                     KEY `is_recursive` (`is_recursive`),
                     KEY `date_mod` (`date_mod`),
                     KEY `date_creation` (`date_creation`)
                  ) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci";
         $DB->query($query) or die($DB->error());
      }
   }

   /**
    * Uninstall previously installed table of the plugin
    *
    * @return boolean True if success
    */
   static function uninstall(Migration $migration) {

      $table = getTableForItemType(__CLASS__);

      $migration->displayMessage("Uninstalling $table");

      $migration->dropTable($table);
   }

}
