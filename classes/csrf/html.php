<?php defined('SYSPATH') OR die('No direct script access.');
/**
 * HTML helper extension with added support for insertion of CSRF meta tags.
 *
 * @package    Protect From Forgery
 * @category   Helpers
 * @author     Gabriel Evans <gabriel@codeconcoction.com>
 * @copyright  (c) 2011 Gabriel Evans
 * @license    http://www.opensource.org/licenses/mit-license.php
 */
class CSRF_HTML extends Kohana_HTML {

	public static function csrf_meta()
	{
		$csrf_token = '<meta'.HTML::attributes(array('name' => 'csrf-token', 'content' => Security::token())).' />';
		$csrf_param = '<meta'.HTML::attributes(array('name' => 'csrf-param', 'content' => Security::$token_name)).' />';

		return $csrf_token."\n".$csrf_param;
	}

} // End CSRF_HTML