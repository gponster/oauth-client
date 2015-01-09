<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth\Exception;

use Gponster\OAuth\Exception\RequestException;

/**
 * Thrown when an unsupported hash mechanism is requested in signature class.
 */
class UnsupportedHashAlgorithmException extends RequestException {
}
