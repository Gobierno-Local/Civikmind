<?php
/*
 * -------------------------------------------------------------------------
 * GLPI - Gestionnaire Libre de Parc Informatique
 * Copyright (C) 2003-2012 by the INDEPNET Development Team.
 *
 * http://indepnet.net/ http://glpi-project.org
 * -------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of GLPI.
 *
 * GLPI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GLPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GLPI. If not, see <http://www.gnu.org/licenses/>.
 * --------------------------------------------------------------------------
 */

// ----------------------------------------------------------------------
// Original Author of file: Julien Dombre
// Purpose of file:
// ----------------------------------------------------------------------

if (! defined('GLPI_ROOT')) {
   die("Sorry. You can't access directly to this file");
}

// / Group_User class - Relation between Group and User
class PluginRoomRoom_Computer extends CommonDBRelation {

   // From CommonDBRelation
   public static $itemtype_1 = 'PluginRoomRoom';

   public static $items_id_1 = 'rooms_id';

   public static $itemtype_2 = 'Computer';

   public static $items_id_2 = 'computers_id';

   public $checks_and_logs_only_for_itemtype1 = true;

}