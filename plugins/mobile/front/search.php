<?php
/*
 * @version $Id: HEADER 10411 2010-02-09 07:58:26Z moyo $
 -------------------------------------------------------------------------
 GLPI - Gestionnaire Libre de Parc Informatique
 Copyright (C) 2003-2010 by the INDEPNET Development Team.

 http://indepnet.net/   http://glpi-project.org
 -------------------------------------------------------------------------

 LICENSE
Inventaire
 This file is part of GLPI.

 GLPI is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 GLPI is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with GLPI; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 --------------------------------------------------------------------------
 */

// ----------------------------------------------------------------------
// Original Author of file:
// Purpose of file:
// ----------------------------------------------------------------------

// Entry menu case

//define('GLPI_ROOT', '../../..'); 
include ("../../../inc/includes.php"); 

$itemtype = $_REQUEST['itemtype'];

$menu_obj = new PluginMobileMenu;
$menu = $menu_obj->getMenu();

if (isset($_REQUEST['menu']) && isset($_REQUEST['ssmenu'])) {
   $welcome = $menu[$_REQUEST['menu']]['content'][$_REQUEST['ssmenu']]['title'];
   $_SESSION['plugin_mobile']['menu'] = $_REQUEST['menu'];
   $_SESSION['plugin_mobile']['ssmenu'] = $_REQUEST['ssmenu'];
   if (isset($_REQUEST['start'])) $_SESSION['plugin_mobile']['start'] = $_REQUEST['start'];
   else $_SESSION['plugin_mobile']['start'] = 0;
}
else $welcome = "&nbsp;";

$common = new PluginMobileCommon;
$common->displayHeader($welcome, "ss_menu.php?menu=".$_REQUEST['menu'], true);

PluginMobileSearch::manageGetValues($itemtype);
//Search::manageParams($itemtype);
$numrows = PluginMobileSearch::show(ucfirst($itemtype));

PluginMobileSearch::displayFooterNavBar("./search.php?itemtype=".$itemtype."&menu=".$_REQUEST['menu']."&ssmenu=".$_REQUEST['ssmenu'], $numrows);

$common->displayFooter();
?>
