<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth;

/**
 * Base token interface for any OAuth version.
 */
interface TokenInterface {

	/**
	 * Denotes an unknown end of life time.
	 */
	const EOL_UNKNOWN = - 9001;

	/**
	 * Denotes a token which never expires, should only happen in OAuth1.
	 */
	const EOL_NEVER_EXPIRES = - 9002;

	/**
	 *
	 * @return string
	 */
	public function getAccessToken();

	/**
	 *
	 * @return int
	 */
	public function getEndOfLife();

	/**
	 *
	 * @return array
	 */
	public function getExtraParams();

	/**
	 *
	 * @param string $accessToken
	 */
	public function setAccessToken($accessToken);

	/**
	 *
	 * @param int $endOfLife
	 */
	public function setEndOfLife($endOfLife);

	/**
	 *
	 * @param int $lifetime
	 */
	public function setLifetime($lifetime);

	/**
	 *
	 * @param array $extraParams
	 */
	public function setExtraParams(array $extraParams);

	/**
	 *
	 * @return string
	 */
	public function getRefreshToken();

	/**
	 *
	 * @param string $refreshToken
	 */
	public function setRefreshToken($refreshToken);

	/**
	 *
	 * @return string
	 */
	public function getAccessTokenSecret();

	/**
	 *
	 * @param string $accessTokenSecret
	 */
	public function setAccessTokenSecret($accessTokenSecret);

	/**
	 *
	 * @return string
	 */
	public function getRequestTokenSecret();

	/**
	 *
	 * @param string $requestTokenSecret
	 */
	public function setRequestTokenSecret($requestTokenSecret);

	/**
	 *
	 * @return string
	 */
	public function getRequestToken();

	/**
	 *
	 * @param string $requestToken
	 */
	public function setRequestToken($requestToken);
}
