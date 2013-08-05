<?php

App::uses('Hash', 'Utility');

class SecuredCore {

	/**
	 * Associative array of controllers & actions that need
	 * to be served from HTTPS instead of regular HTTP.
	 *
	 * @var array
	 */
	public static $secured = array();

	/**
	 * Not Associative array of controllers & actions that allow
	 * to be served from both HTTPS and regular HTTP.
	 *
	 * @var array
	 */
	public static $allowed = array();

	/**
	 * If the current request comes through SSL,
	 * this variable is set to true.
	 *
	 * @var boolean True if request was made through SSL, false otherwise.
	 */
	public static $https = false;

    /**
	 * Whether or not to secure the entire admin route.
	 * Can take either string with the prefix, or an array of the prefixii?
	 *
	 * @var string || array
	 **/
	public static $prefixes = array();

	/**
	 * Whether or not to secure the entire admin route.
	 * Can take either string with the prefix, or an array of the prefixii?
	 *
	 * @param array $config associative array, keys are relevant to properties of this class
	 * @param array $options options array
	 *  -merge boolean whether config
	 **/
	public static function init(array $config, array $options = array()) {
		$options += array(
			'merge' => true,
			'httpsAutoDetect' => true,
		);
		foreach (array('secured', 'allowed', 'prefixes') as $var) {
			$value = isset($config[$var]) ? (array)$config[$var] : array();
			if ($options['merge']) {
				$value = Hash::merge(self::$$var, $value);
			}
			self::$$var = $value;
		}

		if (isset($config['https'])) {
			self::$https = $config['https'];
		} elseif ($options['httpsAutoDetect']) {
			self::$https = self::isSSL();
		}
	}

	public static function isSSL() {
		return in_array(env('HTTPS'), array('on', true), true);
	}

	/**
	 * Determines whether the request (based on passed params)
	 *  is allowed or not.
	 *
	 * @param $params Parameters containing 'controller' and 'action'
	 * @return boolean allowed or not.
	 */

	public static function allowed($params) {
		return static::_judge($params, self::$allowed);
	}

	/**
	 * Determines whether the request (based on passed params)
	 * should be ssl'ed or not.
	 *
	 * @param array $params Parameters containing 'controller' and 'action'
	 * @return boolean True if request should be ssl'ed, false otherwise.
	 */
	public static function ssled($params) {
		//Prefix Specific Check - allow securing of entire admin in one swoop
		if( !empty(self::$prefixes) &&  !empty($params['prefix']) && (in_array($params['prefix'], (array)self::$prefixes)) ) {
			return true;
		}

		return static::_judge($params, self::$secured);
	}

	/**
	 * Helper function to judge the request parameter is in specified actions
	 * or not. Both controller and action can be '*' as wildcard.
	 *
	 * @param array $params Parameters containing 'controller' and 'action'
	 * @param array $config configured actions
	 * @return boolean True if request should be ssl'ed, false otherwise.
	 */
	protected static function _judge($params, $config) {
		foreach (Hash::normalize($config) as $controller => $actions) {
			if ($controller === $params['controller'] || $controller === '*') {
				if ($actions === null || in_array($params['action'], (array)$actions, true) || (array)$actions === array('*')) {
					return true;
				}
			}
		}
		return false;
	}

	public static function url($url, $full = false) {
		if (is_string($url) && preg_match('#(^https?:)?//#', $url)) {
			return $url;
		}

		$originalUrl = $url;
		if (is_array($url)) {
			$url = Router::url($url);
			$url = preg_replace(sprintf('|^%s|', preg_quote(Router::getRequest()->base)), '', $url);
		}
		$url = Router::parse($url);

		if (!self::allowed($url)) {
			$secured = self::ssled($url);

			if ($secured && !self::$https) {
				return SecuredCore::sslUrl(Router::url($originalUrl));
			} elseif (!$secured && self::$https) {
				return SecuredCore::noSslUrl(Router::url($originalUrl));
			}
		}

		return Router::url($originalUrl, $full);
	}

	public static function sslUrl($relativeUrl) {
		$server = env('SERVER_NAME');
		return "https://$server{$relativeUrl}";
	}

	public static function noSslUrl($relativeUrl) {
		$server = env('SERVER_NAME');
		return "http://$server{$relativeUrl}";
	}

}