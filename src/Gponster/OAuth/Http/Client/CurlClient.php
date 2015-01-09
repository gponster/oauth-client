<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth\Http\Client;

use Gponster\OAuth\Exception\RequestException;
use Gponster\OAuth\Exception\ResponseException;
use Gponster\OAuth\Http\Uri\UriInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Client implementation for cURL
 */
class CurlClient extends AbstractClient {

	/**
	 * If true, explicitly sets cURL to use SSL version 3.
	 * Use this if cURL
	 * compiles with GnuTLS SSL.
	 *
	 * @var bool
	 */
	private $forceSsl3 = false;

	/**
	 * Additional parameters (as `key => value` pairs) to be passed to `curl_setopt`
	 *
	 * @var array
	 */
	private $parameters = [];

	/**
	 * Additional `curl_setopt` parameters
	 *
	 * @param array $parameters
	 */
	public function setCurlParameters(array $parameters) {
		$this->parameters = $parameters;
	}

	/**
	 *
	 * @param bool $force
	 *
	 * @return CurlClient
	 */
	public function setForceSsl3($force) {
		$this->forceSsl3 = $force;

		return $this;
	}

	/**
	 * Any implementing HTTP providers should send a request to the provided endpoint with the parameters.
	 * They should return, in string form, the response body and throw an exception on error.
	 *
	 * @param UriInterface $endpoint
	 * @param mixed $requestBody
	 * @param array $extraHeaders
	 * @param string $method
	 *
	 * @return Symfony\Component\HttpFoundation\Response
	 *
	 * @throws ResponseException
	 * @throws RequestException
	 * @throws \InvalidArgumentException
	 */
	public function retrieveResponse(UriInterface $endpoint, $requestBody,
		array $extraHeaders = [], $method = 'POST') {

		// Normalize method name
		$method = strtoupper($method);

		$this->normalizeHeaders($extraHeaders);

		if($method === 'GET' && ! empty($requestBody)) {
			throw new \InvalidArgumentException('No body expected for "GET" request.');
		}

		if(! isset($extraHeaders['Content-type']) && $method === 'POST' &&
			 is_array($requestBody)) {
			$extraHeaders['Content-type'] = 'Content-type: application/x-www-form-urlencoded';
		}

		if($endpoint->isDefaultPort()) {
			$extraHeaders['Host'] = 'Host: ' . $endpoint->getHost() . ':' .
				 $endpoint->getPort();
		} else {
			$extraHeaders['Host'] = 'Host: ' . $endpoint->getHost();
		}

		$extraHeaders['Connection'] = 'Connection: close';

		$ch = curl_init();

		curl_setopt($ch, CURLOPT_URL, $endpoint->getAbsoluteUri());

		if($method === 'POST' || $method === 'PUT') {
			if($requestBody && is_array($requestBody)) {
				$requestBody = http_build_query($requestBody, '', '&');
			}

			if($method === 'PUT') {
				curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
			} else {
				curl_setopt($ch, CURLOPT_POST, true);
			}

			curl_setopt($ch, CURLOPT_POSTFIELDS, $requestBody);
		} else {
			curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
		}

		if($this->maxRedirects > 0) {
			curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
			curl_setopt($ch, CURLOPT_MAXREDIRS, $this->maxRedirects);
		}

		curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_HEADER, true);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $extraHeaders);
		curl_setopt($ch, CURLOPT_USERAGENT, $this->userAgent);

		foreach($this->parameters as $key => $value) {
			curl_setopt($ch, $key, $value);
		}

		if($this->forceSsl3) {
			curl_setopt($ch, CURLOPT_SSLVERSION, 3);
		}

		$data = curl_exec($ch);
		$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

		if(false === $data) {
			$errNo = curl_errno($ch);
			$errStr = curl_error($ch);
			curl_close($ch);

			if(empty($errStr)) {
				throw new RequestException('Failed to request resource.', $status);
			}

			throw new RequestException('cURL Error # ' . $errNo . ': ' . $errStr, $status);
		}

		curl_close($ch);

		list($headers, $body) = explode('\r\n\r\n', $data, 2);

		$parsedHeaders = http_parse_headers($headers);
		$response = new Response($body, $status, $parsedHeaders);

		if((int)$status === 200) {
			return $response;
		} else {
			$e = new ResponseException('HTTP status code $status');
			$e->setResponse($response);
			throw $e;
		}
	}
}
