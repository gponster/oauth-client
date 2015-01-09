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
 * Client implementation for streams/file_get_contents
 */
class StreamClient extends AbstractClient {

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
	 * @throws TokenResponseException
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

		if(is_array($requestBody)) {
			$requestBody = http_build_query($requestBody, '', '&');
		}
		$extraHeaders['Content-length'] = 'Content-length: ' . strlen($requestBody);

		$context = $this->generateStreamContext($requestBody, $extraHeaders, $method);

		$level = error_reporting(0);
		$body = file_get_contents($endpoint->getAbsoluteUri(), false, $context);

		error_reporting($level);

		if(false === $body) {
			$lastError = error_get_last();

			if(is_null($lastError)) {
				throw new RequestException('Failed to request resource.');
			}

			throw new RequestException($lastError['message']);
		}

		// -------------------------------------------------------------------------
		// Gponster <anhvudg@gmail.com> 2013/12/19
		// See https://github.com/Lusitanian/PHPoAuthLib/issues/144
		// -------------------------------------------------------------------------
		$httpResponseHeaders = [];
		list($version, $status, $reason) = explode(' ', $httpResponseHeaders[0], 3);
		$response = new Response($body, $status, $httpResponseHeaders);

		if((int)$status === 200) {
			return $response;
		} else {
			$e = new ResponseException($reason);
			$e->setResponse($response);
			throw $e;
		}
	}

	private function generateStreamContext($body, $headers, $method) {
		return stream_context_create(
			[
				'http' => [
					'method' => $method,
					'header' => implode("\r\n", array_values($headers)),
					'content' => $body, 'protocol_version' => '1.1',
					'user_agent' => $this->userAgent,
					'max_redirects' => $this->maxRedirects, 'timeout' => $this->timeout,
					// ---------------------------------------------------------
					// Gponster <anhvudg@gmail.com> 2013/12/19
					// Fetch the content even on failure status codes. Defaults to FALSE
					// ---------------------------------------------------------
					'ignore_errors' => true
				]
			]);
	}
}
