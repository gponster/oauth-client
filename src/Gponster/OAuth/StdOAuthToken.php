<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth;

/**
 * Standard OAuth1 token implementation.
 * Implements Gponster\OAuth\Token\TokenInterface in case of any OAuth1 specific features.
 */
class StdOAuthToken extends AbstractToken implements TokenInterface {
	/**
	 *
	 * @var string
	 */
	protected $requestToken;

	/**
	 *
	 * @var string
	 */
	protected $requestTokenSecret;

	/**
	 *
	 * @var string
	 */
	protected $accessTokenSecret;

	/**
	 *
	 * @param string $requestToken
	 */
	public function setRequestToken($requestToken) {
		$this->requestToken = $requestToken;
	}

	/**
	 *
	 * @return string
	 */
	public function getRequestToken() {
		return $this->requestToken;
	}

	/**
	 *
	 * @param string $requestTokenSecret
	 */
	public function setRequestTokenSecret($requestTokenSecret) {
		$this->requestTokenSecret = $requestTokenSecret;
	}

	/**
	 *
	 * @return string
	 */
	public function getRequestTokenSecret() {
		return $this->requestTokenSecret;
	}

	/**
	 *
	 * @param string $accessTokenSecret
	 */
	public function setAccessTokenSecret($accessTokenSecret) {
		$this->accessTokenSecret = $accessTokenSecret;
	}

	/**
	 *
	 * @return string
	 */
	public function getAccessTokenSecret() {
		return $this->accessTokenSecret;
	}
}
