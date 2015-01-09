<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth\Http\Client;

use Gponster\OAuth\Http\Uri\UriInterface;
use Gponster\OAuth\Http\Exception\TokenResponseException;

/**
 * Any HTTP clients to be used with the library should implement this interface.
 */
interface ClientInterface {

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
	public function setUserAgent($userAgent, $includeDefault = false);

	/**
	 *
	 * @param int $timeout
	 *        	Request timeout time for client in seconds
	 *
	 * @return ClientInterface
	 */
	public function setTimeout($timeout);

	/**
	 * Any implementing HTTP providers should send a request to the provided endpoint with the parameters.
	 * They should return, in string form, the response body and throw an exception on error.
	 *
	 * @see https://github.com/Lusitanian/PHPoAuthLib/issues/144
	 *
	 * @param UriInterface $endpoint
	 * @param mixed $requestBody
	 * @param array $extraHeaders
	 * @param string $method
	 *
	 * @return Symfony\Component\HttpFoundation\Response
	 *
	 * @throws TokenResponseException
	 */
	public function retrieveResponse(UriInterface $endpoint, $requestBody,
		array $extraHeaders = array(), $method = 'POST');

	/**
	 *
	 * @param string $certificateAuthority
	 * @param string $verifyPeer
	 * @param number $verifyHost
	 */
	public function setSslVerification($certificateAuthority = true, $verifyPeer = true,
		$verifyHost = 2);
}
