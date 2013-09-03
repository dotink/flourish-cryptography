<?php namespace Dotink\Lab
{
	use Dotink\Flourish\Cryptography;
	use Dotink\Parody\Mime;
	use stdClass;

	return [
		'setup' => function($data, $shared) {
			needs($data['root'] . '/src/Cryptography.php');

			$shared->supportFolder = implode(DS, [
				$data['root'],
				'tests',
				'support',
				'cryptography'
			]);

			Mime::define('Dotink\Flourish\Core');

			Mime::create('Dotink\Flourish\Core')
				-> onCall('randomString') -> expect(10) -> give('0123456789');;
		},

		'tests' => [

			//
			//
			//

			'Passwords' => function($data, $shared) {
				$pass = new Cryptography('password123');
				$hash = $pass->hashPassword();

				assert('Dotink\Flourish\Cryptography::checkPasswordHash')
					-> using  ($pass)
					-> with   ($hash)
					-> equals (TRUE)
				;

				assert('Dotink\Flourish\Cryptography::checkPasswordHash')
					-> using  ($pass)
					-> with   ('garbage data')
					-> equals (FALSE)
				;
			},

			//
			//
			//

			'Key Pairs (No Password)' => function($data, $shared) {
				$data    = file_get_contents($shared->supportFolder . DS . 'data.txt');
				$secure  = new Cryptography($data);
				$crypted = $secure->publicKeyEncrypt($shared->supportFolder . DS . 'test_key.crt');

				assert('Dotink\Flourish\Cryptography::publicKeyDecrypt')
					-> using  (new Cryptography($crypted))
					-> with   ($shared->supportFolder . DS . 'test_key.key')
					-> equals ($data)

					-> with   ($shared->supportFolder . DS . 'test_key.pwd.key', 'password123')
					-> equals ($data)
				;
			}
		]
	];
}