<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth\Http\Client;

/**
 * Abstract HTTP client
 */
abstract class AbstractClient implements ClientInterface {

	/**
	 *
	 * @var string The user agent string passed to services
	 */
	protected $userAgent;

	/**
	 *
	 * @var int The maximum number of redirects
	 */
	protected $maxRedirects = 5;

	/**
	 *
	 * @var int The maximum timeout
	 */
	protected $timeout = 15;

	/**
	 * Creates instance
	 *
	 * @param string $userAgent
	 *        	The UA string the client will use
	 */
	public function __construct($userAgent = null) {
		if(empty($userAgent)) {
			$this->userAgent = $this->getDefaultUserAgent();
		} else {
			$this->userAgent = $userAgent;
		}
	}

	/**
	 * Get the default User-Agent string
	 *
	 * @return string
	 */
	public function getDefaultUserAgent() {
		return 'Gponster/OAuth/' . PHP_VERSION;
	}

	/**
	 * Set the User-Agent header to be used on all requests from the client
	 *
	 * @param string $userAgent
	 *        	User agent string
	 * @param bool $includeDefault
	 *        	Set to true to prepend the value to the default user agent string
	 *
	 * @return self
	 */
	public function setUserAgent($userAgent, $includeDefault = false) {
		if($includeDefault) {
			$userAgent .= ' ' . $this->getDefaultUserAgent();
		}

		$this->userAgent = $userAgent;
		return $this;
	}

	/**
	 *
	 * @param int $maxRedirects
	 *        	Maximum redirects for client
	 *
	 * @return ClientInterface
	 */
	public function setMaxRedirects($redirects) {
		$this->maxRedirects = $redirects;

		return $this;
	}

	/**
	 *
	 * @param int $timeout
	 *        	Request timeout time for client in seconds
	 *
	 * @return ClientInterface
	 */
	public function setTimeout($timeout) {
		$this->timeout = $timeout;

		return $this;
	}

	/**
	 *
	 * @param array $headers
	 */
	public function normalizeHeaders(&$headers) {
		// Normalize headers
		array_walk($headers,
			function (&$val, &$key) {
				$key = ucfirst(strtolower($key));
				$val = ucfirst(strtolower($key)) . ': ' . $val;
			});
	}

	public function setSslVerification($certificateAuthority = true, $verifyPeer = true,
		$verifyHost = 2) {
	}
}
