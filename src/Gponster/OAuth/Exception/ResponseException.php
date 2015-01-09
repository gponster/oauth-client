<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth\Exception;

/**
 * An exception that allows for a given response message to be returned to the client.
 */
class ResponseException extends OAuthException {
	/**
	 *
	 * @var \Symfony\Component\HttpFoundation\Response
	 */
	protected $response;

	/**
	 *
	 * @return \Symfony\Component\HttpFoundation\Response
	 */
	public function getResponse() {
		return $this->response;
	}

	/**
	 *
	 * @param \Symfony\Component\HttpFoundation\Response $response
	 */
	public function setResponse($response) {
		$this->response = $response;
	}

	/**
	 *
	 * @param \Symfony\Component\HttpFoundation\Response $response
	 * @return array
	 */
	public static function parseError($response) {
		$result = [];

		$code = $response->getStatusCode();
		$body = $response->getContent();

		$obj = json_decode($body, true);
		if(json_last_error() == JSON_ERROR_NONE) {
			$result = $obj['result'];

			if(is_array($result['errors']) && sizeof($result['errors']) > 0) {
				$result['first_error'] = $result['errors'][0];
			}
		}

		return $result;
	}
}