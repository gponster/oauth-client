<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth;

use Gponster\OAuth\TokenStorageInterface;
use Gponster\OAuth\CredentialsInterface;
use Gponster\OAuth\Http\Client\ClientInterface;
use Gponster\OAuth\Http\Uri\UriInterface;
use Gponster\OAuth\SignatureInterface;
use Gponster\OAuth\Exception\TokenResponseException;
use Gponster\OAuth\Exception\ResponseException;

/**
 * Abstract OAuth service, version-agnostic
 */
abstract class AbstractService {

	/**
	 *
	 * @var CredentialsInterface
	 */
	protected $credentials;

	/**
	 *
	 * @var ClientInterface
	 */
	protected $httpClient;

	/**
	 *
	 * @var TokenStorageInterface
	 */
	protected $storage;

	/**
	 *
	 * @var SignatureInterface
	 */
	protected $signature;

	/**
	 * Request token URL
	 *
	 * @var UriInterface|null
	 */
	protected $requestTokenUri;

	/**
	 * xAuth URL
	 *
	 * @var UriInterface|null
	 */
	protected $authUri;

	/**
	 * Authorization URL
	 *
	 * @var UriInterface|null
	 */
	protected $authzUri;

	/**
	 * Access token URL
	 *
	 * @var UriInterface|null
	 */
	protected $accessTokenUri;

	/**
	 * Base URL
	 *
	 * @var UriInterface|null
	 */
	protected $baseUri;

	/**
	 * @const OAUTH_VERSION
	 */
	const OAUTH_VERSION = 1;

	/**
	 *
	 * @param Credentials $credentials
	 * @param ClientInterface $httpClient
	 * @param TokenStorageInterface $storage
	 */
	public function __construct(CredentialsInterface $credentials,
		ClientInterface $httpClient, TokenStorageInterface $storage,
		SignatureInterface $signature, UriInterface $baseUri = null) {

		// Initialize
		$this->credentials = $credentials;
		$this->httpClient = $httpClient;
		$this->storage = $storage;

		$this->signature = $signature;
		$this->baseUri = $baseUri;

		$this->signature->setHashingAlgorithm($this->getSignatureMethod());
	}

	/**
	 *
	 * @param UriInterface|string $path
	 * @param UriInterface $baseUri
	 *
	 * @return UriInterface
	 *
	 * @throws Exception
	 */
	protected function determineRequestUriFromPath($path, UriInterface $baseUri = null) {
		if($path instanceof UriInterface) {
			$uri = $path;
		} elseif(stripos($path, 'http://') === 0 || stripos($path, 'https://') === 0) {
			$uri = new Uri($path);
		} else {
			if(null === $baseUri) {
				throw new \Exception(
					'An absolute URI must be passed to request as no baseUri is set.');
			}

			$uri = clone $baseUri;
			if(false !== strpos($path, '?')) {
				$parts = explode('?', $path, 2);
				$path = $parts[0];
				$query = $parts[1];
				$uri->setQuery($query);
			}

			if($path[0] === '/') {
				$path = substr($path, 1);
			}

			$uri->setPath($uri->getPath() . $path);
		}

		return $uri;
	}

	/**
	 * Accessor to the storage adapter to be able to retrieve tokens
	 *
	 * @return TokenStorageInterface
	 */
	public function getStorage() {
		return $this->storage;
	}

	/**
	 * Accessor to the http client
	 *
	 * @return TokenStorageInterface
	 */
	public function getHttpClient() {
		return $this->httpClient;
	}

	/**
	 *
	 * @throws \Gponster\OAuth\Exception\TokenResponseException
	 * @return \Gponster\OAuth\TokenInterface
	 */
	public function requestRequestToken() {
		$authorizationHeader = [
			'Authorization' => $this->buildAuthorizationHeaderForTokenRequest()
		];

		$headers = array_merge($authorizationHeader, $this->getExtraOAuthHeaders());

		try {
			$response = $this->httpClient->retrieveResponse($this->getRequestTokenUri(),
				array(), $headers);
			$token = $this->parseRequestTokenResponse($response->getContent());
			$this->storage->storeRequestToken($this->getServiceName(), $token);

			return $token;
		} catch(ResponseException $re) {
			$e = new TokenResponseException(
				sprintf('Error in retrieving token. The HTTP status code %s', $code));
			$e->setResponse($re->getResponse());
			throw $e;
		}
	}

	/**
	 *
	 * @param array $additionalParameters
	 * @return UriInterface
	 */
	public function buildAuthorizationUri(array $additionalParameters = array()) {
		// Build the url
		$url = clone $this->getAuthorizationUri();
		foreach($additionalParameters as $key => $val) {
			$url->addToQuery($key, $val);
		}

		return $url;
	}

	/**
	 *
	 * @param unknown $token
	 * @param unknown $verifier
	 * @param string $tokenSecret
	 * @throws \Gponster\OAuth\Exception\TokenResponseException
	 * @return \Gponster\OAuth\TokenInterface
	 */
	public function requestAccessToken($token, $verifier, $tokenSecret = null) {
		if(is_null($tokenSecret)) {
			$storedRequestToken = $this->storage->retrieveAccessToken(
				$this->getServiceName());
			$tokenSecret = $storedRequestToken->getRequestTokenSecret();
		}

		$this->signature->setTokenSecret($tokenSecret);

		$extraAuthenticationHeaders = [
			'oauth_token' => $token
		];

		$bodyParams = [
			'oauth_verifier' => $verifier
		];

		$authorizationHeader = [
			'Authorization' => $this->buildAuthorizationHeaderForApiRequest('POST',
				$this->getAccessTokenUri(),
				$this->storage->retrieveAccessToken($this->getServiceName()), $bodyParams)
		];

		$headers = array_merge($authorizationHeader, $this->getExtraOAuthHeaders());

		try {
			$response = $this->httpClient->retrieveResponse($this->getAccessTokenUri(),
				$bodyParams, $headers);
			$token = $this->parseAccessTokenResponse($response->getContent());
			$this->storage->storeAccessToken($this->getServiceName(), $token);

			return $token;
		} catch(ResponseException $re) {
			$e = new TokenResponseException(
				sprintf('Error in retrieving token. The HTTP status code %s', $code));
			$e->setResponse($re->getResponse());
			throw $e;
		}
	}

	/**
	 * Sends an un-authenticated API request to the path provided.
	 * If the path provided is not an absolute URI, the base API Uri (service-specific) will be used.
	 *
	 * @param string|UriInterface $path
	 * @param string $method
	 *        	HTTP method
	 * @param array $body
	 *        	Request body if applicable (an associative array will
	 *        	automatically be converted into a urlencoded body)
	 * @param array $extraHeaders
	 *        	Extra headers if applicable. These will override service-specific
	 *        	any defaults.
	 *
	 * @return string
	 */
	public function requestZeroLeg($path, $method = 'GET', $body = null, array $extraHeaders = []) {
		$uri = $this->determineRequestUriFromPath($path, $this->baseUri);

		// OAuth authorization header
		$parameters = $this->getBasicAuthorizationHeaderInfo();
		$parameters = array_merge($parameters, $extraHeaders);
		$parameters['oauth_callback'] = 'oob';

		$mergedParams = array_merge($parameters, $body);

		// ---------------------------------------------------------------------
		// Gponster <anhvudg@gmail> 2014/04/05
		// Reset token secret, we no need token secret here, if set token secret must send oauth_token
		// ---------------------------------------------------------------------
		$this->signature->setTokenSecret(null);

		$parameters['oauth_signature'] = $this->signature->getSignature($uri,
			$mergedParams, $method);

		$oauthAuthzHeader = 'OAuth ';
		$delimiter = '';
		foreach($parameters as $key => $value) {
			$oauthAuthzHeader .= $delimiter . rawurlencode($key) . '="' .
				 rawurlencode($value) . '"';
			$delimiter = ', ';
		}

		$authorizationHeader = [
			'Authorization' => $oauthAuthzHeader
		];

		$headers = array_merge($authorizationHeader, $this->getExtraOAuthHeaders());

		return $this->httpClient->retrieveResponse($uri, $body, $headers, $method);
	}

	/**
	 * Sends an authenticated API request to the path provided.
	 * If the path provided is not an absolute URI, the base API Uri (must be passed into constructor) will be used.
	 *
	 * @param string|UriInterface $path
	 * @param string $method
	 *        	HTTP method
	 * @param array $body
	 *        	Request body if applicable (key/value pairs)
	 * @param array $extraHeaders
	 *        	Extra headers if applicable.
	 *        	These will override service-specific any defaults.
	 *
	 * @return string
	 */
	public function request($path, $method = 'GET', $body = null, array $extraHeaders = array()) {
		$uri = $this->determineRequestUriFromPath($path, $this->baseUri);

		/**
		 *
		 * @var $token StdOAuthToken
		 */
		$token = $this->storage->retrieveAccessToken($this->getServiceName());
		$extraHeaders = array_merge($this->getExtraApiHeaders(), $extraHeaders);

		// ---------------------------------------------------------------------
		// NOT INCLUDE FILE UPLOAD CONTENT - DIRTY FIXED
		// Gponster <anhvudg@gmail.com> 2014/04/05
		// ---------------------------------------------------------------------
		$authzBody = $body;
		if(isset($authzBody['file'])) {
			if(strpos($authzBody['file'], '@') === 0) {
				unset($authzBody['file']);
			}
		}

		$authorizationHeader = [
			'Authorization' => $this->buildAuthorizationHeaderForApiRequest($method, $uri,
				$token, $authzBody)
		];

		$headers = array_merge($authorizationHeader, $extraHeaders);
		return $this->httpClient->retrieveResponse($uri, $body, $headers, $method);
	}

	/**
	 * Return any additional headers always needed for this service implementation's OAuth calls.
	 *
	 * @return array
	 */
	protected function getExtraOAuthHeaders() {
		return [];
	}

	/**
	 * Return any additional headers always needed for this service implementation's API calls.
	 *
	 * @return array
	 */
	protected function getExtraApiHeaders() {
		return [];
	}

	/**
	 * Builds the authorization header for getting an access or request token.
	 *
	 * @param array $extraParameters
	 *
	 * @return string
	 */
	protected function buildAuthorizationHeaderForTokenRequest(array $extraParameters = []) {
		$parameters = $this->getBasicAuthorizationHeaderInfo();
		$parameters = array_merge($parameters, $extraParameters);
		$parameters['oauth_signature'] = $this->signature->getSignature(
			$this->getRequestTokenUri(), $parameters, 'POST');

		$authorizationHeader = 'OAuth ';
		$delimiter = '';
		foreach($parameters as $key => $value) {
			$authorizationHeader .= $delimiter . rawurlencode($key) . '="' .
				 rawurlencode($value) . '"';

			$delimiter = ', ';
		}

		return $authorizationHeader;
	}

	/**
	 * Builds the authorization header for an authenticated API request
	 *
	 * @param string $method
	 * @param UriInterface $uri
	 *        	The uri the request is headed
	 * @param TokenInterface $token
	 * @param array $bodyParams
	 *        	Request body if applicable (key/value pairs)
	 *
	 * @return string
	 */
	protected function buildAuthorizationHeaderForApiRequest($method, UriInterface $uri,
		TokenInterface $token, $bodyParams = null) {
		$this->signature->setTokenSecret($token->getAccessTokenSecret());
		$parameters = $this->getBasicAuthorizationHeaderInfo();
		if(isset($parameters['oauth_callback'])) {
			unset($parameters['oauth_callback']);
		}

		$parameters = array_merge($parameters,
			[
				'oauth_token' => $token->getAccessToken()
			]);

		$mergedParams = (is_array($bodyParams)) ? array_merge($parameters, $bodyParams) : $parameters;

		$parameters['oauth_signature'] = $this->signature->getSignature($uri,
			$mergedParams, $method);

		$authorizationHeader = 'OAuth ';
		$delimiter = '';

		foreach($parameters as $key => $value) {
			$authorizationHeader .= $delimiter . rawurlencode($key) . '="' .
				 rawurlencode($value) . '"';
			$delimiter = ', ';
		}

		return $authorizationHeader;
	}

	/**
	 * Builds the authorization header array.
	 *
	 * @return array
	 */
	protected function getBasicAuthorizationHeaderInfo() {
		$dateTime = new \DateTime();
		$headerParameters = [
			'oauth_callback' => $this->credentials->getCallbackUrl(),
			'oauth_consumer_key' => $this->credentials->getConsumerId(),
			'oauth_nonce' => $this->generateNonce(),
			'oauth_signature_method' => $this->getSignatureMethod(),
			'oauth_timestamp' => $dateTime->format('U'),
			'oauth_version' => $this->getVersion()
		];

		return $headerParameters;
	}

	/**
	 * Pseudo random string generator used to build a unique string to sign each request
	 *
	 * @param int $length
	 *
	 * @return string
	 */
	protected function generateNonce($length = 32) {
		$characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';

		$nonce = '';
		$maxRand = strlen($characters) - 1;
		for($i = 0; $i < $length; $i ++) {
			$nonce .= $characters[rand(0, $maxRand)];
		}

		return $nonce;
	}

	/**
	 *
	 * @return string
	 */
	protected function getSignatureMethod() {
		return 'HMAC-SHA1';
	}

	/**
	 * This returns the version used in the authorization header of the requests
	 *
	 * @return string
	 */
	protected function getVersion() {
		return '1.0';
	}

	/**
	 * Returns the access token API endpoint.
	 *
	 * @return UriInterface
	 */
	public function getRequestTokenUri() {
		return $this->requestTokenUri;
	}

	/**
	 * Set the authorization API endpoint.
	 *
	 * @param UriInterface|string $uri
	 */
	public function setRequestTokenUri($uri) {
		$this->requestTokenUri = $this->determineRequestUriFromPath($uri);
	}

	/**
	 * Returns the access token API endpoint.
	 *
	 * @return UriInterface
	 */
	public function getAuthUri() {
		return $this->authUri;
	}

	/**
	 * Set the authorization API endpoint.
	 *
	 * @param UriInterface|string $uri
	 */
	public function setAuthUri($uri) {
		$this->authUri = $this->determineRequestUriFromPath($uri);
	}

	/**
	 * Returns the authorization API endpoint.
	 *
	 * @return UriInterface
	 */
	public function getAuthorizationUri() {
		return $this->authzUri;
	}

	/**
	 * Set the authorization API endpoint.
	 *
	 * @param UriInterface|string $uri
	 */
	public function setAuthorizationUri($uri) {
		$this->authzUri = $this->determineRequestUriFromPath($uri);
	}

	/**
	 * Returns the access token API endpoint.
	 *
	 * @return UriInterface
	 */
	public function getAccessTokenUri() {
		return $this->accessTokenUri;
	}

	/**
	 * Set the access token API endpoint.
	 *
	 * @param UriInterface|string $uri
	 */
	public function setAccessTokenUri($uri) {
		$this->accessTokenUri = $this->determineRequestUriFromPath($uri);
	}

	/**
	 * Returns base API URI
	 *
	 * @return UriInterface
	 */
	public function getBaseUri() {
		return $this->baseUri;
	}

	/**
	 * Set the base API URI
	 *
	 * @param UriInterface|string $uri
	 */
	public function setBaseUri($uri) {
		$this->baseUri = $this->determineRequestUriFromPath($uri);
	}

	/**
	 * Parses the request token response and returns a TokenInterface.
	 * This is only needed to verify the `oauth_callback_confirmed` parameter. The actual
	 * parsing logic is contained in the access token parser.
	 *
	 * @abstract
	 *
	 * @param string $responseBody
	 * @return TokenInterface
	 * @throws TokenResponseException
	 */
	abstract protected function parseRequestTokenResponse($responseBody);

	/**
	 * Parses the access token response and returns a TokenInterface.
	 *
	 * @abstract
	 *
	 * @param string $responseBody
	 * @return TokenInterface
	 * @throws TokenResponseException
	 */
	abstract protected function parseAccessTokenResponse($responseBody);

	/**
	 */
	abstract protected function getServiceName();
}