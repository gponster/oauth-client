<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth;

use Gponster\OAuth\Http\Client\ClientInterface;
use Gponster\OAuth\Http\Uri\UriInterface;
use Gponster\OAuth\Exception\TokenResponseException;
use Gponster\OAuth\Exception\ResponseException;
use Gponster\OAuth\Http\Uri\Uri;

class Client extends AbstractService {

	public function __construct(CredentialsInterface $credentials,
		ClientInterface $httpClient, TokenStorageInterface $storage,
		SignatureInterface $signature, UriInterface $baseUri = null) {

		// Parent constructor
		parent::__construct($credentials, $httpClient, $storage, $signature, $baseUri);
	}

	public static function make($options = []) {
		$options = is_array($options) ? $options : [];

		// Get storage object
		if(isset($options['storage'])) {
			$storageClassName = $options['storage'];

			if(! class_exists($storageClassName)) {
				throw new \RuntimeException(
					sprintf('Token storage class \'%s\' does not exist.',
						$storageClassName));
			}

			$reflClass = new \ReflectionClass($storageClassName);
			if(! $reflClass->implementsInterface('Gponster\\OAuth\\TokenStorageInterface')) {
				throw new \RuntimeException(
					sprintf(
						'Token storage class \'%s\' must implements interface Gponster\\OAuth\\TokenStorageInterface.',
						$validatorName));
			}
		} else {
			$storageClassName = '\\Gponster\\OAuth\\SessionStorage';
		}

		$storage = new $storageClassName();

		// Get HTTP client object
		if(isset($options['http_client'])) {
			$httpClientClassName = $options['http_client'];

			if(! class_exists($httpClientClassName)) {
				throw new \RuntimeException(
					sprintf('HTTP client class \'%s\' does not exist.', $httpClientClassName));
			}

			$reflClass = new \ReflectionClass($httpClientClassName);
			if(! $reflClass->implementsInterface(
				'Gponster\\OAuth\\Http\\Client\\ClientInterface')) {
				throw new \RuntimeException(
					sprintf(
						'User validator class \'%s\' must implements interface Gponster\\OAuth\\Http\\Client\\ClientInterface.',
						$validatorName));
			}
		} else {
			$httpClientClassName = '\\Gponster\\OAuth\\Http\\Client\\GuzzleClient';
		}

		$httpClient = new $httpClientClassName();

		$userAgent = isset($options['user_agent']) ? $options['user_agent'] : null;
		$httpClient->setUserAgent($userAgent);

		// Create credentials object
		$credentials = new Credentials($options['client_id'], $options['client_secret'],
			isset($options['callback_url']) ? $options['callback_url'] : 'oob');

		// Get scope from config (default to empty array)
		$scope = isset($options['scope']) ? $options['scope'] : [];

		$baseUrl = isset($options['base_url']) ? new Uri($options['base_url']) : null;

		// Return the service consumer object
		$client = new Client($credentials, $httpClient, $storage,
			new Signature($credentials), $baseUrl);

		// Set endpoint
		$accessTokenUrl = isset($options['access_token_url']) ? $options['access_token_url'] : null;
		if(! empty($accessTokenUrl)) {
			$client->setAccessTokenUri($accessTokenUrl);
		}

		$authorizeUrl = isset($options['authorize_url']) ? $options['authorize_url'] : null;
		if(! empty($authorizeUrl)) {
			$client->setAuthorizationUri($authorizeUrl);
		}

		$requestTokenUrl = isset($options['request_token_url']) ? $options['request_token_url'] : null;
		if(! empty($requestTokenUrl)) {
			$client->setRequestTokenUri($requestTokenUrl);
		}

		$authUrl = isset($options['auth_url']) ? $options['auth_url'] : null;
		if(! empty($authUrl)) {
			$client->setAuthUri($authUrl);
		}

		return $client;
	}

	/**
	 * (non-PHPdoc)
	 *
	 * @see \Gponster\OAuth\AbstractService::getServiceName()
	 */
	public function getServiceName() {
		return 'Gponster\OAuth';
	}

	/**
	 *
	 * @param array $data
	 * @return array:
	 */
	protected function parseExtraParams($data) {
		if(isset($data['user_id'])) {
			$data['id'] = $data['user_id'];
			unset($data['user_id']);
		}

		$profile = [
			'first_name' => isset($data['first_name']) ? $data['first_name'] : null,
			'last_name' => isset($data['last_name']) ? $data['last_name'] : null,
			'email' => isset($data['email']) ? $data['email'] : null
		];

		$data['profile'] = array_merge($profile,
			isset($data['profile']) ? $data['profile'] : []);

		if(isset($data['device_id'])) {
			$device = [
				'id' => $data['device_id'],
				'name' => isset($data['device_name']) ? $data['device_name'] : null,
				'kind' => isset($data['kind']) ? $data['kind'] : null,
				'fingerprint' => isset($data['fingerprint']) ? $data['fingerprint'] : null
			];

			$data['device'] = array_merge($device,
				isset($data['device']) ? $data['device'] : array());
		} elseif(isset($data['device'])) {
			$data['device_id'] = $data['device']['id'];
		}

		unset($data['oauth_token']);
		unset($data['oauth_token_secret']);

		return $data;
	}

	/**
	 *
	 * @param mixed $response
	 * @throws TokenResponseException
	 * @return array|TokenResponseException
	 */
	protected function parseTokenResponse($response) {
		$data = json_decode($response, true);

		if(json_last_error() == JSON_ERROR_NONE) {
			if(! isset($data['oauth_token_secret'])) {
				throw new TokenResponseException('Unable to parse response.');
			}

			$token = $data['oauth_token'];
			$tokenSecret = $data['oauth_token_secret'];
			unset($data['oauth_token'], $data['oauth_token_secret']);

			$attrs = $this->parseExtraParams($data);
			return [
				'oauth_token' => $token, 'oauth_token_secret' => $tokenSecret,
				'extra_params' => $attrs
			];
		} else {
			parse_str($response, $data);

			if(null === $data || ! is_array($data)) {
				throw new TokenResponseException('Unable to parse response.');
			} elseif(isset($data['error'])) {
				throw new TokenResponseException(
					'Error in retrieving token: "' . $data['error'] . '"');
			} elseif(! isset($data['oauth_token_secret']) || ! isset($data['oauth_token'])) {
				throw new TokenResponseException('No token response.');
			}

			$token = $data['oauth_token'];
			$tokenSecret = $data['oauth_token_secret'];
			unset($data['oauth_token'], $data['oauth_token_secret']);

			$attrs = $this->parseExtraParams($data);
			return [
				'oauth_token' => $token, 'oauth_token_secret' => $tokenSecret,
				'extra_params' => $attrs
			];
		}
	}

	/**
	 * (non-PHPdoc)
	 *
	 * @see \Gponster\OAuth\AbstractService::parseRequestTokenResponse()
	 */
	protected function parseRequestTokenResponse($response) {
		$parsedResp = $this->parseTokenResponse($response);

		$token = new StdOAuthToken();

		$token->setRequestToken($parsedResp['oauth_token']);
		$token->setRequestTokenSecret($parsedResp['oauth_token_secret']);

		$token->setEndOfLife(StdOAuthToken::EOL_NEVER_EXPIRES);
		$token->setExtraParams($parsedResp['extra_params']);

		return $token;
	}

	/**
	 * (non-PHPdoc)
	 *
	 * @see \Gponster\OAuth\AbstractService::parseAccessTokenResponse()
	 */
	protected function parseAccessTokenResponse($response) {
		$parsedResp = $this->parseTokenResponse($response);

		$token = new StdOAuthToken();

		$token->setAccessToken($parsedResp['oauth_token']);
		$token->setAccessTokenSecret($parsedResp['oauth_token_secret']);

		$token->setEndOfLife(StdOAuthToken::EOL_NEVER_EXPIRES);
		$token->setExtraParams($parsedResp['extra_params']);

		return $token;
	}

	/**
	 * Do authenticate using xAuth with username and password.
	 *
	 * @param string $username
	 * @param string $password
	 * @param string $method
	 *        	HTTP method
	 * @param array $params
	 *        	Request body if applicable (an associative array will
	 *        	automatically be converted into a urlencoded body)
	 * @param array $extraHeaders
	 *        	Extra headers if applicable. These will override service-specific
	 *        	any defaults.
	 *
	 * @return string
	 */
	public function auth($username, $password, $login = true, $method = 'GET', $params = null,
		array $extraHeaders = []) {
		$body = [];

		// Check username/password arguments
		if(empty($username)) {
			throw new \InvalidArgumentException('x_auth_username is required');
		}

		if(empty($password)) {
			throw new \InvalidArgumentException('x_auth_password is required');
		}

		$body = array_merge($body, is_array($params) ? $params : array());
		if(! isset($body['x_auth_mode'])) {
			$body['x_auth_mode'] = 'client_auth';
		}

		// Unset duplicate
		unset($body['x_auth_username']);
		unset($body['x_auth_password']);

		$body['x_auth_username'] = $username;
		$body['x_auth_password'] = $password;

		// Set up web device
		$body['device_name'] = $_SERVER['SERVER_NAME'] . ' Website';
		$body['kind'] = 'website|' . $_SERVER['SERVER_NAME'];

		$platformName = 'platform_name=' . php_uname('s') . ' PHP ' . phpversion();
		$platformVersion = 'platform_version=' . php_uname('v');
		$productName = 'product_name=' . 'PHP ' . phpversion();
		$productModel = 'product_model=' . $_SERVER['SERVER_SOFTWARE'];

		$body['info'] = implode('|',
			[
				$platformName, $platformVersion, $productName, $productModel
			]);

		// Info
		$body['info'] = base64_encode($body['info']);

		// Using app.key as fingerprint
		$body['fingerprint'] = base64_encode(sha1($body['info'], true));

		try {
			$response = $this->requestZeroLeg($this->getAuthUri(), 'POST', $body);

			$token = self::parseAccessTokenResponse($response->getContent());

			// Login
			if($login) {
				$this->storage->storeAccessToken($this->getServiceName(), $token);
			}

			return $response;
		} catch(ResponseException $re) {
			$e = new TokenResponseException(
				sprintf('Error in retrieving token. %s', $re->getMessage()));
			$e->setResponse($re->getResponse());
			throw $e;
		}
	}

	/**
	 * If path not is xAuth URL: sends an authenticated API request to the path provided.
	 * If path is xAuth URL: do xAuth authenticate not required access token
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
	public function request($path, $method = 'GET', $body = null, array $extraHeaders = []) {
		if($path === $this->getAuthUri()) {
			if(! is_array($body)) {
				throw new \InvalidArgumentException('Body parameter must be an array');
			}

			// Check username/password arguments
			if(! isset($body['x_auth_username'])) {
				throw new \InvalidArgumentException('x_auth_username is required');
			}

			if(! isset($body['x_auth_password'])) {
				throw new \InvalidArgumentException('x_auth_password is required');
			}

			$username = $body['x_auth_username'];
			unset($body['x_auth_username']);

			$password = $body['x_auth_password'];
			unset($body['x_auth_password']);

			// Default login=true
			$login = isset($body['login']) ? $body['login'] : true;
			unset($body['login']);

			$login = isset($login) ? $login : false;

			return $this->auth($username, $password, $login, $method, $body,
				$extraHeaders);
		} else {
			$token = $this->storage->retrieveAccessToken($this->getServiceName());
			$extra = $token->getExtraParams();

			$deviceId = null;
			if(! empty($extra['device_id'])) {
				$deviceId = $extra['device_id'];
			} elseif(isset($extra['device'])) {
				$device = $extra['device'];

				if(isset($device['id'])) {
					$deviceId = $device['id'];
				}
			}

			if(! is_array($body)) {
				$body = [];
			}

			$body = array_merge($body, [
				'device_id' => $deviceId
			]);

			return parent::request($path, $method, $body, $extraHeaders);
		}
	}
}
