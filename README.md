# oauth-client
- **Author**: Gponster

Simple OAuth 1 client based-on PHP 5.3+ oAuth 1/2 Client Library.

## Installation ##

Firstly you want to include this package in your composer.json file.

    "require": {
    		"gponster/oauth-client": "dev-master"
    }
    
Now you'll want to update or install via composer.

    composer update

Configuration is pretty easy too, include vendor/autoload.php:

require_once ('path/to/vendor/autoload.php');

Using existing Client or create your own consumer class:

```php
$client = \Gponster\OAuth\Client::make(
	[
		'client_id' => 'a7xxxxx',
		'client_secret' => '9bwxxxx',
		'base_url' => 'https://api.xxx.com/v1'
	]);

$ret = $client->requestZeroLeg('/users/stats', 'POST',
	[
		'event' => $event, 'role_id' => $post['role_id'],
		'account' => $post['pname'], 'ip' => $post['ip'],
		'plat' => PLAT_NAME
	]);
```

The options to create Client instance

$options['storage'] class implement TokenStorageInterface
$options['http_client'] class implement ClientInterface
$options['user_agent'] User Agent

$options['callback_url'] callback URL default 'oob'
$options['access_token_url']
$options['authorize_url']
$options['request_token_url']
