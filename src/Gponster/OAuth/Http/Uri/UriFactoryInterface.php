<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth\Http\Uri;

/**
 * Factory interface for uniform resource indicators
 */
interface UriFactoryInterface {

	/**
	 * Factory method to build a URI from a super-global $_SERVER array.
	 *
	 * @param array $_server
	 *
	 * @return UriInterface
	 */
	public function createFromSuperGlobalArray(array $_server);

	/**
	 * Creates a URI from an absolute URI
	 *
	 * @param string $absoluteUri
	 *
	 * @return UriInterface
	 */
	public function createFromAbsolute($absoluteUri);

	/**
	 * Factory method to build a URI from parts
	 *
	 * @param string $scheme
	 * @param string $userInfo
	 * @param string $host
	 * @param string $port
	 * @param string $path
	 * @param string $query
	 * @param string $fragment
	 *
	 * @return UriInterface
	 */
	public function createFromParts($scheme, $userInfo, $host, $port, $path = '',
		$query = '', $fragment = '');
}
