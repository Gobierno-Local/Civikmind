<?php
/*
 * @version $Id: HEADER 15930 2011-10-30 15:47:55Z tsmr $
 -------------------------------------------------------------------------
 Manufacturersimports plugin for GLPI
 Copyright (C) 2003-2016 by the Manufacturersimports Development Team.

 https://github.com/InfotelGLPI/manufacturersimports
 -------------------------------------------------------------------------

 LICENSE

 This file is part of Manufacturersimports.

 Manufacturersimports is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 Manufacturersimports is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Manufacturersimports. If not, see <http://www.gnu.org/licenses/>.
 --------------------------------------------------------------------------
 */

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access directly to this file");
}

/**
 * Class PluginManufacturersimportsFujitsu
 */
class PluginManufacturersimportsFujitsu extends PluginManufacturersimportsManufacturer {

   /**
    * @see PluginManufacturersimportsManufacturer::showDocTitle()
    */
   function showDocTitle($output_type, $header_num) {
      return Search::showHeaderItem($output_type, __('File'), $header_num);
   }

   function getSearchField() {
      return "Service Start Date";
   }

   /**
    * @see PluginManufacturersimportsManufacturer::getSupplierInfo()
    */
   function getSupplierInfo($compSerial = null, $otherSerial = null, $key = null, $apisecret = null,
                            $supplierUrl = null) {
      $info["name"]         = PluginManufacturersimportsConfig::FUJITSU;
      $info["supplier_url"] = "http://support.ts.fujitsu.com/Warranty/WarrantyStatus.asp?lng=com&IDNR=";
      $info["url"]          = $supplierUrl.$compSerial."&Version=3.51";

      return $info;
   }

   /**
    * @see PluginManufacturersimportsManufacturer::getBuyDate()
    */
   function getBuyDate($contents) {

      $matchesarray = [];
      preg_match_all("/(\d{2}\/\d{2}\/\d{4})/", $contents, $matchesarray);

      $datetimestamp = date('U');
      $myDate = $matchesarray[0][0];

      $myDate = trim($myDate);
      $myDate = str_replace('/', '-', $myDate);

      $myDate = PluginManufacturersimportsPostImport::checkDate($myDate, true);

      if ($myDate != "0000-00-00") {
         list($day, $month, $year) = explode('-', $myDate);
         $myDate = date("Y-m-d", mktime(0, 0, 0, $month, $day, $year));
      }
      return $myDate;
   }

   /**
    * @see PluginManufacturersimportsManufacturer::getStartDate()
    */
   function getStartDate($contents) {

      return self::getBuyDate($contents);
   }


   /**
    * @see PluginManufacturersimportsManufacturer::getExpirationDate()
    */
   function getExpirationDate($contents) {

      $matchesarray = [];
      preg_match_all("/(\d{2}\/\d{2}\/\d{4})/", $contents, $matchesarray);

      $datetimestamp = date('U');
      $myDate = $matchesarray[0][1];

      $myDate = trim($myDate);
      $myDate = str_replace('/', '-', $myDate);

      $myDate = PluginManufacturersimportsPostImport::checkDate($myDate, true);

      if ($myDate != "0000-00-00") {
         list($day, $month, $year) = explode('-', $myDate);
         $myDate = date("Y-m-d", mktime(0, 0, 0, $month, $day, $year));
      }
      return $myDate;
   }
}
