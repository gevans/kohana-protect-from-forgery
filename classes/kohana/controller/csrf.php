<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Abstract CSRF controller class. Adds support for automatically validating
 * CSRF tokens for external requests.
 *
 * @package    Protect From Forgery
 * @category   Controller
 * @author     Gabriel Evans <gabriel@codeconcoction.com>
 * @copyright  (c) 2011 Gabriel Evans
 * @license    http://www.opensource.org/licenses/mit-license.php
 */
abstract class Kohana_Controller_CSRF extends Controller {

	/**
	 * Checks external non-GET requests for a valid CSRF token. If a token is
	 * missing or invalid, it will attempt to redirect to the referrer,
	 * most likely a form, or throw an exception when the referrer is `NULL`.
	 *
	 * @uses    Security::protect_from_forgery
	 * @throws  CSRF_Validation_Exception
	 */
	public function before()
	{
		// Validate the request
		Security::protect_from_forgery($this->request);

		parent::before();
	}

} // End Controller_CSRF