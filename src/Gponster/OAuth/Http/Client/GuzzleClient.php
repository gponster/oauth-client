<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth\Http\Client;

use Gponster\OAuth\Exception\ResponseException;
use Gponster\OAuth\Http\Uri\UriInterface;
use Symfony\Component\HttpFoundation\Response;

/**
 * Client implementation for Guzzle
 */
class GuzzleClient extends AbstractClient {
	/**
	 *
	 * @var \GuzzleHttp\Client
	 */
	protected $client;

	/**
	 *
	 * @var \Symfony\Component\HttpFoundation\Response
	 */
	protected $lastResponse;

	/**
	 * Any implementing HTTP providers should send a request to the provided endpoint with the parameters.
	 * They should return, in string form, the response body and throw an exception on error.
	 *
	 * @param UriInterface $endpoint
	 * @param mixed $requestBody
	 * @param array $extraHeaders
	 * @param string $method
	 *
	 * @return \Symfony\Component\HttpFoundation\Response
	 *
	 * @throws \Gponster\OAuth\Exception\ResponseException
	 * @throws \InvalidArgumentException
	 */
	public function retrieveResponse(UriInterface $endpoint, $body,
		array $extraHeaders = [], $method = 'POST') {
		try {
			$request = $this->client()
				->createRequest($method, $endpoint->getAbsoluteUri(),
				$method === 'GET' ? [] : $body);
			$request->setHeaders($extraHeaders);

			if($method === 'GET' && is_array($body)) {
				$request->getQuery()
					->merge($body);
			}

			$response = $this->lastResponse = $this->client()
				->send($request);
			return new Response($response->getBody(), $response->getStatusCode(),
				$response->getHeaders());
		} catch(\GuzzleHttp\Exception\RequestException $re) {

			$httpErrorResponse = null;
			$statusCode = 0;
			$content = '';
			$headers = [];

			if($re->hasResponse()) {
				$httpErrorResponse = $re->getResponse();

				$headers = $httpErrorResponse->getHeaders();
				$statusCode = $httpErrorResponse->getStatusCode();
				$body = $httpErrorResponse->getBody();

				$unreadBytes = $body->getMetadata()['unread_bytes'];
				if($unreadBytes > 0) {
					$content = $body->getContents();
				} else {
					$content = (string)$body;
				}
			}

			$e = new ResponseException($re->getMessage());
			$this->lastResponse = $httpErrorResponse;

			if($statusCode != 0) {
				$e->setResponse(new Response($content, $statusCode, $headers));
			}

			throw $e;
		}
	}

	private function client() {
		if(! isset($this->client)) {
			$this->client = new \GuzzleHttp\Client();
		}

		return $this->client;
	}

	public function getOriginalResponse() {
		return $this->lastResponse;
	}

	public function getLastResponse() {
		return $this->lastResponse;
	}
}