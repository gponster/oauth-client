<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth;

/**
 * Credentials Interface, credentials should implement this.
 */
interface CredentialsInterface {

	/**
	 *
	 * @return string
	 */
	public function getCallbackUrl();

	/**
	 *
	 * @return string
	 */
	public function getConsumerId();

	/**
	 *
	 * @return string
	 */
	public function getConsumerSecret();
}
