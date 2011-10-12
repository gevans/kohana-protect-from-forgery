<?php defined('SYSPATH') OR die('No direct script access.');
/**
 * Form helper extension with added support for hidden CSRF token fields.
 *
 * @package    Protect From Forgery
 * @category   Helpers
 * @author     Gabriel Evans <gabriel@codeconcoction.com>
 * @copyright  (c) 2011 Gabriel Evans
 * @license    http://www.opensource.org/licenses/mit-license.php
 */
class CSRF_Form extends Kohana_Form {

	/**
	 * @uses Security::token
	 */
	public static function csrf_param(array $attributes = array())
	{
		$attributes['autocomplete'] = 'off';

		return Form::hidden(Security::$token_name, Security::token(), $attributes);
	}

} // End CSRF_Form