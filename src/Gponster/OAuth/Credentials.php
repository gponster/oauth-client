<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth;

/**
 * Value object for the credentials of an OAuth service.
 */
class Credentials implements CredentialsInterface {

	/**
	 *
	 * @var string
	 */
	protected $consumerId;

	/**
	 *
	 * @var string
	 */
	protected $consumerSecret;

	/**
	 *
	 * @var string
	 */
	protected $callbackUrl;

	/**
	 *
	 * @param string $consumerId
	 * @param string $consumerSecret
	 * @param string $callbackUrl
	 */
	public function __construct($consumerId, $consumerSecret, $callbackUrl) {
		$this->consumerId = $consumerId;
		$this->consumerSecret = $consumerSecret;
		$this->callbackUrl = $callbackUrl;
	}

	/**
	 *
	 * @return string
	 */
	public function getCallbackUrl() {
		return $this->callbackUrl;
	}

	/**
	 *
	 * @return string
	 */
	public function getConsumerId() {
		return $this->consumerId;
	}

	/**
	 *
	 * @return string
	 */
	public function getConsumerSecret() {
		return $this->consumerSecret;
	}
}
