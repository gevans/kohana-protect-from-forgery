<?php defined('SYSPATH') or die('No direct script access.');
/**
 * Security helper extension for supporting multiple CSRF tokens with
 * expirations, improved hashing, easier configuration, and drop-in
 * support for validation.
 *
 * @package    Protect From Forgery
 * @category   Security
 * @author     Gabriel Evans <gabriel@codeconcoction.com>
 * @copyright  (c) 2011 Gabriel Evans
 * @license    http://www.opensource.org/licenses/mit-license.php
 */
class CSRF_Security extends Kohana_Security
{
	/**
	 * @var  string  current request token
	 */
	public static $token = NULL;

	/**
	 * @var  integer  time in seconds until a token expires
	 */
	public static $token_lifetime = 900;

	/**
	 * @var  integer  max number of tokens stored in a single session
	 */
	public static $token_limit = 50;

	/**
	 * @var  string  key used for hashing tokens
	 */
	public static $token_secret = NULL;

	/**
	 * @var  string  string appended to tokens prior to hashing
	 */
	public static $token_salt = NULL;

	/**
	 * @var  string  token key name used for session storage, forms, and headers
	 */
	public static $token_name = 'authenticity_token';

	/**
	 * Check that the given token matches the currently stored security token.
	 *
	 *     if (Security::check($token))
	 *     {
	 *         // Pass
	 *     }
	 *
	 * @param   string   token to check
	 * @return  boolean
	 * @uses    Session::instance
	 */
	public static function check($token)
	{
		$session = Session::instance();

		// Retrieve tokens from session
		$tokens = $session->get(Security::$token_name, array());

		if (isset($tokens[$token]) AND $tokens[$token] > time())
		{
			// Token found, remove it from the array
			unset($tokens[$token]);

			// Store the updated tokens array
			$session->set(Security::$token_name, $tokens);

			return TRUE;
		}

		return FALSE;
	}

	/**
	 * Generate and store a unique token which can be used to help prevent
	 * [CSRF](http://wikipedia.org/wiki/Cross_Site_Request_Forgery) attacks.
	 *
	 *     $token = Security::token();
	 *
	 * You can insert this token into your forms as a hidden field:
	 *
	 *     echo Form::csrf_param();
	 *
	 * And then check it when using [Validation]:
	 *
	 *     $array->rules(Security::$token_name, array(
	 *         'not_empty'       => NULL,
	 *         'Security::check' => NULL,
	 *     ));
	 *
	 * Or check it in a `before()` filter in your controllers:
	 *
	 *     public function before()
	 *     {
	 *         $this->protect_from_forgery();
	 *     }
	 *
	 * This provides a basic, but effective, method of preventing CSRF attacks.
	 *
	 * @param   boolean  force a new token to be generated?
	 * @return  string
	 * @uses    Session::instance
	 * @see     Controller::protect_from_forgery
	 */
	public static function token($new = FALSE)
	{
		if (Security::$token === NULL)
		{
			$session = Session::instance();

			// Get the current tokens
			$tokens = $session->get(Security::$token_name);

			if (count($tokens) > Security::$token_limit)
			{
				// Remove oldest token from the array
				array_shift($tokens);
			}

			// Generate a new unique token
			Security::$token = $token = base64_encode(hash_hmac('sha256', uniqid(NULL, TRUE).Security::$token_salt, Security::$token_secret, TRUE));

			// Add to tokens and give an expiration
			$tokens[$token] = time() + Security::$token_lifetime;

			// Store the updated tokens array
			$session->set(Security::$token_name, $tokens);
		}

		return Security::$token;
	}

	/**
	 * Checks external non-GET requests for a valid CSRF token. If a token is
	 * missing or invalid, it will attempt to redirect to the referrer,
	 * most likely a form, or throw an exception when the referrer is `NULL`.
	 *
	 * @param   Request  $request   Request instance
	 * @param   mixed    $callback  Callback for validation success
	 * @return  void
	 * @throws  CSRF_Validation_Exception
	 */
	public static function protect_from_forgery(Request $request, $callback = NULL)
	{
		if ( ! $request->is_external() OR $request->method() === Request::GET)
		{
			// Skip validation for internal and GET requests
			return;
		}

		if ($request->post(Security::$token_name) !== NULL)
		{
			// Set the token from POST parameters
			$token = $request->post(Security::$token_name);
		}
		else
		{
			// If the CSRF token is missing in the POST params, fallback to header
			$token = $request->headers('x-csrf-token');
		}

		if (Security::check($token))
		{
			if ($callback !== NULL)
			{
				// Send success to callback
				call_user_func($callback, TRUE);
			}
		}
		else
		{
			if ($callback !== NULL)
			{
				// Send failure to callback
				call_user_func($callback, FALSE);
			}

			if ($request->referrer() !== NULL)
			{
				// If the client has a referrer, redirect to it
				$request->redirect($request->referrer());
			}
			else
			{
				// If the client has no referrer, throw an informative exception
				throw new CSRF_Validation_Exception('Expected valid CSRF token parameter, :token_name, or X-CSRF-Token header', array(
					':token_name' => Security::$token_name,
				));
			}
		}
	}

} // End Security