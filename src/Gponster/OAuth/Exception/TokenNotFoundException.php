<?php

/**
 * Based on PHP 5.3+ oAuth 1/2 Client Library
 * @see https://github.com/Lusitanian/PHPoAuthLib
 * @author     Gponster <anhvudg@gmail.com>
 */
namespace Gponster\OAuth\Exception;

/**
 * Exception thrown when a token is not found in storage.
 */
class TokenNotFoundException extends StorageException {
}
