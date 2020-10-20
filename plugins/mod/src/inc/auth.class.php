<?php
/**
 * ---------------------------------------------------------------------
 * GLPI - Gestionnaire Libre de Parc Informatique
 * Copyright (C) 2015-2018 Teclib' and contributors.
 *
 * http://glpi-project.org
 *
 * based on GLPI - Gestionnaire Libre de Parc Informatique
 * Copyright (C) 2003-2014 by the INDEPNET Development Team.
 *
 * ---------------------------------------------------------------------
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GLPI. If not, see <http://www.gnu.org/licenses/>.
 * ---------------------------------------------------------------------
 */

use Glpi\Event;

if (!defined('GLPI_ROOT')) {
   die("Sorry. You can't access this file directly");
}

/**
 *  Identification class used to login
 */
class Auth extends CommonGLPI {

   //Errors
   private $errors = [];
   /** User class variable
    * @see User
    */
   public $user;
   //! External authentification variable : boolean
   public $extauth = 0;
   // External authentifications methods;
   public $authtypes;
   // Indicates if the user is authenticated or not
   public $auth_succeded = 0;
   // Indicates if the user is already present in database
   public $user_present = 0;
   // Indicates if the user is deleted in the directory (doesn't mean that it can login)
   public $user_deleted_ldap = 0;
   // LDAP connection descriptor
   public $ldap_connection;
   // Store user LDAP dn
   public $user_dn = false;

   const DB_GLPI  = 1;
   const MAIL     = 2;
   const LDAP     = 3;
   const EXTERNAL = 4;
   const CAS      = 5;
   const X509     = 6;
   const API      = 7;
   const COOKIE   = 8;
   const NOT_YET_AUTHENTIFIED = 0;

   const USER_DOESNT_EXIST       = 0;
   const USER_EXISTS_WITH_PWD    = 1;
   const USER_EXISTS_WITHOUT_PWD = 2;

   /**
    * Constructor
    *
    * @return void
    */
   function __construct() {
      $this->user = new User();
   }

   /**
    *
    * @return boolean
    *
    * @since 0.85
    */
   static function canView() {
      return Session::haveRight('config', READ);
   }

   static function getMenuContent() {

      $menu = [];
      if (Config::canUpdate()) {
            $menu['title']                              = __('Authentication');
            $menu['page']                               = '/front/setup.auth.php';

            $menu['options']['ldap']['title']           = AuthLDAP::getTypeName(Session::getPluralNumber());
            $menu['options']['ldap']['page']            = AuthLDAP::getSearchURL(false);
            $menu['options']['ldap']['links']['search'] = AuthLDAP::getSearchURL(false);
            $menu['options']['ldap']['links']['add']    = AuthLDAP::getFormURL(false);

            $menu['options']['imap']['title']           = AuthMail::getTypeName(Session::getPluralNumber());
            $menu['options']['imap']['page']            = AuthMail::getSearchURL(false);
            $menu['options']['imap']['links']['search'] = AuthMail::getSearchURL(false);
            $menu['options']['imap']['links']['add']    = AuthMail::getFormURL(false);

            $menu['options']['others']['title']         = __('Others');
            $menu['options']['others']['page']          = '/front/auth.others.php';

            $menu['options']['settings']['title']       = __('Setup');
            $menu['options']['settings']['page']        = '/front/auth.settings.php';
      }
      if (count($menu)) {
         return $menu;
      }
      return false;
   }

   /**
    * Check user existence in DB
    *
    * @var DBmysql $DB
    *
    * @param array $options conditions : array('name'=>'glpi')
    *                                    or array('email' => 'test at test.com')
    *
    * @return integer Auth::USER_DOESNT_EXIST, Auth::USER_EXISTS_WITHOUT_PWD or Auth::USER_EXISTS_WITH_PWD
    */
   function userExists($options = []) {
      global $DB;

      $result = $DB->request('glpi_users',
         ['WHERE'    => $options,
         'LEFT JOIN' => ['glpi_useremails' => ['FKEY' => ['glpi_users'      => 'id',
                                                          'glpi_useremails' => 'users_id']]]]);
      // Check if there is a row
      if ($result->numrows() == 0) {
         $this->addToError(__('Incorrect username or password'));
         return self::USER_DOESNT_EXIST;
      } else {
         // Get the first result...
         $row = $result->next();

         // Check if we have a password...
         if (empty($row['password'])) {
            //If the user has an LDAP DN, then store it in the Auth object
            if ($row['user_dn']) {
               $this->user_dn = $row['user_dn'];
            }
            return self::USER_EXISTS_WITHOUT_PWD;

         }
         return self::USER_EXISTS_WITH_PWD;
      }
   }

   /**
    * Try a IMAP/POP connection
    *
    * @param string $host  IMAP/POP host to connect
    * @param string $login Login to try
    * @param string $pass  Password to try
    *
    * @return boolean connection success
    */
   function connection_imap($host, $login, $pass) {

      // we prevent some delay...
      if (empty($host)) {
         return false;
      }

      $oldlevel = error_reporting(16);
      // No retry (avoid lock account when password is not correct)
      if ($mbox = imap_open($host, $login, $pass, null, 1)) {
         imap_close($mbox);
         error_reporting($oldlevel);
         return true;
      }
      $this->addToError(imap_last_error());

      error_reporting($oldlevel);
      return false;
   }

   /**
    * Find a user in a LDAP and return is BaseDN
    * Based on GRR auth system
    *
    * @param string $ldap_method ldap_method array to use
    * @param string $login       User Login
    * @param string $password    User Password
    *
    * @return string basedn of the user / false if not founded
    */
   function connection_ldap($ldap_method, $login, $password) {

      // we prevent some delay...
      if (empty($ldap_method['host'])) {
         return false;
      }

      $this->ldap_connection   = AuthLdap::tryToConnectToServer($ldap_method, $login, $password);
      $this->user_deleted_ldap = false;

      if ($this->ldap_connection) {
         $params = [
            'method' => AuthLDAP::IDENTIFIER_LOGIN,
            'fields' => [
               AuthLDAP::IDENTIFIER_LOGIN => $ldap_method['login_field'],
            ],
         ];
         if (!empty($ldap_method['sync_field'])) {
            $params['fields']['sync_field'] = $ldap_method['sync_field'];
         }
         $infos = AuthLdap::searchUserDn($this->ldap_connection,
                                         ['basedn'            => $ldap_method['basedn'],
                                               'login_field'       => $ldap_method['login_field'],
                                               'search_parameters' => $params,
                                               'user_params'
                                                   => ['method' => AuthLDAP::IDENTIFIER_LOGIN,
                                                            'value'  => $login],
                                                   'condition'         => $ldap_method['condition'],
                                                   'user_dn'           => $this->user_dn]);
         $dn = $infos['dn'];
         if (!empty($dn) && @ldap_bind($this->ldap_connection, $dn, $password)) {

            //Hook to implement to restrict access by checking the ldap directory
            if (Plugin::doHookFunction("restrict_ldap_auth", $infos)) {
               return $infos;
            }
            $this->addToError(__('User not authorized to connect in GLPI'));
            //Use is present by has no right to connect because of a plugin
            return false;

         } else {
            // Incorrect login
            $this->addToError(__('Incorrect username or password'));
            //Use is not present anymore in the directory!
            if ($dn == '') {
               $this->user_deleted_ldap = true;
            }
            return false;
         }

      } else {
         $this->addToError(__('Unable to connect to the LDAP directory'));
         //Directory is not available
         return false;
      }
   }

   /**
    * Check is a password match the stored hash
    *
    * @since 0.85
    *
    * @param string $pass Passowrd
    * @param string $hash Hash
    *
    * @return boolean
    */
   static function checkPassword($pass, $hash) {

      $tmp = password_get_info($hash);

      if (isset($tmp['algo']) && $tmp['algo']) {
         $ok = password_verify($pass, $hash);

      } else if (strlen($hash)==32) {
         $ok = md5($pass) === $hash;

      } else if (strlen($hash)==40) {
         $ok = sha1($pass) === $hash;

      } else {
         $salt = substr($hash, 0, 8);
         $ok = ($salt.sha1($salt.$pass) === $hash);
      }

      return $ok;
   }

   /**
    * Is the hash stored need to be regenerated
    *
    * @since 0.85
    *
    * @param string $hash Hash
    *
    * @return boolean
    */
   static function needRehash($hash) {

      return password_needs_rehash($hash, PASSWORD_DEFAULT);
   }

   /**
    * Compute the hash for a password
    *
    * @since 0.85
    *
    * @param string $pass Password
    *
    * @return string
    */
   static function getPasswordHash($pass) {

      return password_hash($pass, PASSWORD_DEFAULT);
   }

   /**
    * Find a user in the GLPI DB
    *
    * try to connect to DB
    * update the instance variable user with the user who has the name $name
    * and the password is $password in the DB.
    * If not found or can't connect to DB updates the instance variable err
    * with an eventual error message
    *
    * @var DBmysql $DB
    * @param string $name     User Login
    * @param string $password User Password
    *
    * @return boolean user in GLPI DB with the right password
    */
   function connection_db($name, $password) {
      global $DB;

      // SQL query
      $result = $DB->request('glpi_users', ['FIELDS' => ['id', 'password'], 'name' => $name,
         'authtype' => $this::DB_GLPI, 'auths_id' => 0]);

      // Have we a result ?
      if ($result->numrows() == 1) {
         $row = $result->next();
         $password_db = $row['password'];

         if (self::checkPassword($password, $password_db)) {
            // Update password if needed
            if (self::needRehash($password_db)) {
               $input = [
                  'id' => $row['id'],
               ];
               // Set glpiID to allow password update
               $_SESSION['glpiID'] = $input['id'];
               $input['password'] = $password;
               $input['password2'] = $password;
               $user = new User();
               $user->update($input);
            }
            $this->user->getFromDBByCrit(['id' => $row['id']]);
            $this->extauth                  = 0;
            $this->user_present             = 1;
            $this->user->fields["authtype"] = self::DB_GLPI;
            $this->user->fields["password"] = $password;
            return true;
         }
      }
      $this->addToError(__('Incorrect username or password'));
      return false;
   }

   /**
    * Try to get login of external auth method
    *
    * @param integer $authtype external auth type (default 0)
    *
    * @return boolean user login success
    */
   function getAlternateAuthSystemsUserLogin($authtype = 0) {
      global $CFG_GLPI;

      switch ($authtype) {
         case self::CAS :
            if (!Toolbox::canUseCAS()) {
               Toolbox::logError("CAS lib not installed");
               return false;
            }

            phpCAS::client(constant($CFG_GLPI["cas_version"]), $CFG_GLPI["cas_host"], intval($CFG_GLPI["cas_port"]),
                           $CFG_GLPI["cas_uri"], false);

            // no SSL validation for the CAS server
            phpCAS::setNoCasServerValidation();

            // force CAS authentication
            phpCAS::forceAuthentication();
            $this->user->fields['name'] = phpCAS::getUser();

            // extract e-mail information
            if (phpCAS::hasAttribute("mail")) {
                $this->user->fields['_useremails'] = [phpCAS::getAttribute("mail")];
            }

            return true;

         case self::EXTERNAL :
            $ssovariable = Dropdown::getDropdownName('glpi_ssovariables',
                                                     $CFG_GLPI["ssovariables_id"]);
            $login_string = '';
            // MoYo : checking REQUEST create a security hole for me !
            if (isset($_SERVER[$ssovariable])) {
               $login_string = $_SERVER[$ssovariable];
            }
            // else {
            //    $login_string = $_REQUEST[$ssovariable];
            // }
            $login        = $login_string;
            $pos          = stripos($login_string, "\\");
            if (!$pos === false) {
               $login = substr($login_string, $pos + 1);
            }
            if ($CFG_GLPI['existing_auth_server_field_clean_domain']) {
               $pos = stripos($login, "@");
               if (!$pos === false) {
                  $login = substr($login, 0, $pos);
               }
            }
            if (self::isValidLogin($login)) {
               $this->user->fields['name'] = $login;
               // Get data from SSO if defined
               $ret = $this->user->getFromSSO();
               if (!$ret) {
                  return false;
               }
               return true;
            }
            break;

         case self::X509 :
            // From eGroupWare  http://www.egroupware.org
            // an X.509 subject looks like:
            // CN=john.doe/OU=Department/O=Company/C=xx/Email=john@comapy.tld/L=City/
            $sslattribs = explode('/', $_SERVER['SSL_CLIENT_S_DN']);
            $sslattributes = [];
            while ($sslattrib = next($sslattribs)) {
               list($key,$val)      = explode('=', $sslattrib);
               $sslattributes[$key] = $val;
            }
            if (isset($sslattributes[$CFG_GLPI["x509_email_field"]])
                && NotificationMailing::isUserAddressValid($sslattributes[$CFG_GLPI["x509_email_field"]])
                && self::isValidLogin($sslattributes[$CFG_GLPI["x509_email_field"]])) {

               $restrict = false;
               $CFG_GLPI["x509_ou_restrict"] = trim($CFG_GLPI["x509_ou_restrict"]);
               if (!empty($CFG_GLPI["x509_ou_restrict"])) {
                  $split = explode ('$', $CFG_GLPI["x509_ou_restrict"]);

                  if (!in_array($sslattributes['OU'], $split)) {
                     $restrict = true;
                  }
               }
               $CFG_GLPI["x509_o_restrict"] = trim($CFG_GLPI["x509_o_restrict"]);
               if (!empty($CFG_GLPI["x509_o_restrict"])) {
                  $split = explode ('$', $CFG_GLPI["x509_o_restrict"]);

                  if (!in_array($sslattributes['O'], $split)) {
                     $restrict = true;
                  }
               }
               $CFG_GLPI["x509_cn_restrict"] = trim($CFG_GLPI["x509_cn_restrict"]);
               if (!empty($CFG_GLPI["x509_cn_restrict"])) {
                  $split = explode ('$', $CFG_GLPI["x509_cn_restrict"]);

                  if (!in_array($sslattributes['CN'], $split)) {
                     $restrict = true;
                  }
               }

               if (!$restrict) {
                  $this->user->fields['name'] = $sslattributes[$CFG_GLPI["x509_email_field"]];

                  // Can do other things if need : only add it here
                  $this->user->fields['email'] = $this->user->fields['name'];
                  return true;
               }
            }
            break;

         case self::API:
            if ($CFG_GLPI['enable_api_login_external_token']) {
               $user = new User();
               if ($user->getFromDBbyToken($_REQUEST['user_token'], 'api_token')) {
                  $this->user->fields['name'] = $user->fields['name'];
                  return true;
               }
            } else {
               $this->addToError(__("Login with external token disabled"));
            }
            break;
         case self::COOKIE:
            $cookie_name = session_name() . '_rememberme';
            $cookie_path = ini_get('session.cookie_path');

            if ($CFG_GLPI["login_remember_time"]) {
               $data = json_decode($_COOKIE[$cookie_name], true);
               if (count($data) === 2) {
                  list ($cookie_id, $cookie_token) = $data;

                  $user = new User();
                  $user->getFromDB($cookie_id);
                  $hash = $user->getAuthToken('cookie_token');

                  if (Auth::checkPassword($cookie_token, $hash)) {
                     $this->user->fields['name'] = $user->fields['name'];
                     return true;
                  } else {
                     $this->addToError(__("Invalid cookie data"));
                  }
               }
            } else {
               $this->addToError(__("Auto login disabled"));
            }

            //Remove cookie to allow new login
            setcookie($cookie_name, '', time() - 3600, $cookie_path);
            unset($_COOKIE[$cookie_name]);
            break;
      }
      return false;
   }

   /**
    * Get the current identification error
    *
    * @return string current identification error
    */
   function getErr() {
      return implode("<br>\n", $this->getErrors());
   }

   /**
    * Get errors
    *
    * @since 9.4
    *
    * @return array
    */
   public function getErrors() {
      return $this->errors;
   }

   /**
    * Get the current user object
    *
    * @return object current user
    */
   function getUser() {
      return $this->user;
   }

   /**
    * Get all the authentication methods parameters
    * and return it as an array
    *
    * @return void
    */
   function getAuthMethods() {

      //Return all the authentication methods in an array
      $this->authtypes = [
         'ldap' => getAllDatasFromTable('glpi_authldaps'),
         'mail' => getAllDatasFromTable('glpi_authmails')
      ];
   }

   /**
    * Add a message to the global identification error message
    *
    * @param string $message the message to add
    *
    * @return void
    */
   function addToError($message) {
      if (!in_array($message, $this->errors)) {
         $this->errors[] = $message;
      }
   }

   /**
    * Manage use authentication and initialize the session
    *
    * @param string  $login_name     Login
    * @param string  $login_password Password
    * @param boolean $noauto         (false by default)
    * @param string $login_auth      type of auth - id of the auth
    *
    * @return boolean (success)
   */
   function login($login_name, $login_password, $noauto = false, $remember_me = false, $login_auth = '') {
      global $DB, $CFG_GLPI;

      $this->getAuthMethods();
      $this->user_present  = 1;
      $this->auth_succeded = false;
      //In case the user was deleted in the LDAP directory
      $user_deleted_ldap   = false;

      // Trim login_name : avoid LDAP search errors
      $login_name = trim($login_name);

      // manage the $login_auth (force the auth source of the user account)
      $this->user->fields["auths_id"] = 0;
      if ($login_auth == 'local') {
         $authtype = self::DB_GLPI;
         $this->user->fields["authtype"] = self::DB_GLPI;
      } else if (strstr($login_auth, '-')) {
         $auths = explode('-', $login_auth);
         $this->user->fields["auths_id"] = $auths[1];
         if ($auths[0] == 'ldap') {
            $authtype = self::LDAP;
            $this->user->fields["authtype"] = self::LDAP;
         } else if ($auths[0] == 'mail') {
            $authtype = self::MAIL;
            $this->user->fields["authtype"] = self::MAIL;
         } else if ($auths[0] == 'external') {
            $authtype = self::EXTERNAL;
            $this->user->fields["authtype"] = self::EXTERNAL;
         }
      }
      if (!$noauto && ($authtype = self::checkAlternateAuthSystems())) {
         if ($this->getAlternateAuthSystemsUserLogin($authtype)
             && !empty($this->user->fields['name'])) {
            // Used for log when login process failed
            $login_name                        = $this->user->fields['name'];
            $this->auth_succeded               = true;
            $this->user_present                = $this->user->getFromDBbyName(addslashes($login_name));
            $this->extauth                     = 1;
            $user_dn                           = false;

            if (array_key_exists('_useremails', $this->user->fields)) {
                $email = $this->user->fields['_useremails'];
            }

            $ldapservers = [];
            //if LDAP enabled too, get user's infos from LDAP
            if (Toolbox::canUseLdap()) {
               //User has already authenticate, at least once : it's ldap server if filled
               if (isset($this->user->fields["auths_id"])
                   && ($this->user->fields["auths_id"] > 0)) {
                  $authldap = new AuthLdap();
                  //If ldap server is enabled
                  if ($authldap->getFromDB($this->user->fields["auths_id"])
                      && $authldap->fields['is_active']) {
                     $ldapservers[] = $authldap->fields;
                  }
               } else { // User has never beeen authenticated : try all active ldap server to find the right one
                  foreach (getAllDatasFromTable('glpi_authldaps', ['is_active' => 1]) as $ldap_config) {
                     $ldapservers[] = $ldap_config;
                  }
               }

               $ldapservers_status = false;
               foreach ($ldapservers as $ldap_method) {
                  $ds = AuthLdap::connectToServer($ldap_method["host"],
                                                  $ldap_method["port"],
                                                  $ldap_method["rootdn"],
                                                  Toolbox::decrypt($ldap_method["rootdn_passwd"]),
                                                  $ldap_method["use_tls"],
                                                  $ldap_method["deref_option"]);

                  if ($ds) {
                     $ldapservers_status = true;
                     $params = [
                        'method' => AuthLdap::IDENTIFIER_LOGIN,
                        'fields' => [
                           AuthLdap::IDENTIFIER_LOGIN => $ldap_method["login_field"],
                        ],
                     ];
                     try {
                        $user_dn = AuthLdap::searchUserDn($ds, [
                           'basedn'            => $ldap_method["basedn"],
                           'login_field'       => $ldap_method['login_field'],
                           'search_parameters' => $params,
                           'condition'         => $ldap_method["condition"],
                           'user_params'       => [
                              'method' => AuthLDAP::IDENTIFIER_LOGIN,
                              'value'  => $login_name
                           ],
                        ]);
                     } catch (\RuntimeException $e) {
                        Toolbox::logError($e->getMessage());
                        $user_dn = false;
                     }
                     if ($user_dn) {
                        $this->user->fields['auths_id'] = $ldap_method['id'];
                        $this->user->getFromLDAP($ds, $ldap_method, $user_dn['dn'], $login_name,
                                                 !$this->user_present);
                        break;
                     }
                  }
               }
            }
            if ((count($ldapservers) == 0)
                && ($authtype == self::EXTERN