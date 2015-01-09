<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth;

use Gponster\OAuth\TokenInterface;
use Gponster\OAuth\Exception\TokenNotFoundException;

/**
 * All token storage providers must implement this interface.
 */
interface TokenStorageInterface {

	/**
	 *
	 * @param string $service
	 *
	 * @return TokenInterface
	 *
	 * @throws TokenNotFoundException
	 */
	public function retrieveAccessToken($service);

	/**
	 *
	 * @param string $service
	 * @param TokenInterface $token
	 *
	 * @return TokenStorageInterface
	 */
	public function storeAccessToken($service, TokenInterface $token);

	/**
	 *
	 * @param string $service
	 *
	 * @return bool
	 */
	public function hasAccessToken($service);

	/**
	 * Delete the users token.
	 * Aka, log out.
	 *
	 * @param string $service
	 *
	 * @return TokenStorageInterface
	 */
	public function clearToken($service);

	/**
	 * Delete *ALL* user tokens.
	 * Use with care. Most of the time you will likely
	 * want to use clearToken() instead.
	 *
	 * @return TokenStorageInterface
	 */
	public function clearAllTokens();
}
