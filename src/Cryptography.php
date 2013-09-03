<?php namespace Dotink\Flourish
{
	/**
	 * Provides session-based messaging for page-to-page communication
	 *
	 * @copyright  Copyright (c) 2007-2012 Will Bond, others
	 * @author     Will Bond           [wb]  <will@flourishlib.com>
	 * @author     Matthew J. Sahagian [mjs] <msahagian@dotink.org>
	 *
	 * @license    Please reference the LICENSE.md file at the root of this distribution
	 *
	 * @package    Flourish
	 */
	class Cryptography
	{
		/**
		 * The data we're working with
		 *
		 * @access private
		 * @var string
		 */
		private $data = NULL;


		/**
		 * Create a private key resource based on a filename and password
		 *
		 * @throws ValidationException  When the private key is invalid
		 *
		 * @static
		 * @access private
		 * @param  string $private_key_file  The path to a PEM-encoded private key
		 * @param  string $password          The password for the private key
		 * @return resource  The private key resource
		 */
		static private function createPrivateKeyResource($private_key_file, $password)
		{
			if (!file_exists($private_key_file)) {
				throw new ProgrammerException(
					'The path to the PEM-encoded private key specified, %s, is not valid',
					$private_key_file
				);
			}
			if (!is_readable($private_key_file)) {
				throw new EnvironmentException(
					'The PEM-encoded private key specified, %s, is not readable',
					$private_key_file
				);
			}

			$private_key          = file_get_contents($private_key_file);
			$private_key_resource = openssl_pkey_get_private($private_key, $password);

			if ($private_key_resource === FALSE) {
				throw new ValidationException(
					'The private key file specified, %s, does not appear to be a valid ' .
					'private key or the password provided is incorrect',
					$private_key_file
				);
			}

			return $private_key_resource;
		}


		/**
		 * Create a public key resource based on a filename
		 *
		 * @static
		 * @access private
		 * @param  string $public_key_file  The path to an X.509 public key certificate
		 * @return resource  The public key resource
		 */
		static private function createPublicKeyResource($public_key_file)
		{
			if (!file_exists($public_key_file)) {
				throw new ProgrammerException(
					'The path to the X.509 certificate specified, %s, is not valid',
					$public_key_file
				);
			}

			if (!is_readable($public_key_file)) {
				throw new EnvironmentException(
					'The X.509 certificate specified, %s, can not be read',
					$public_key_file
				);
			}

			$public_key          = file_get_contents($public_key_file);
			$public_key_resource = openssl_pkey_get_public($public_key);

			if ($public_key_resource === FALSE) {
				throw new ProgrammerException(
					'The public key certificate specified, %s, does not appear to be a ' .
					'valid certificate',
					$public_key_file
				);
			}

			return $public_key_resource;
		}


		/**
		 * Performs a large iteration of hashing a string with a salt
		 *
		 * @static
		 * @access private
		 * @param  string $source The string to hash
		 * @param  string $salt The salt for the hash
		 * @return string An 80 character string of the Flourish fingerprint, salt and hashed password
		 */
		static private function hashWithSalt($source, $salt)
		{
			$hash = sha1($salt . $source);

			for ($i = 0; $i < 1000; $i++) {
				$hash = sha1($hash . (($i % 2 == 0) ? $source : $salt));
			}

			return sprintf(
				'%s::password_hash#%s#%s',
				__CLASS__,
				$salt,
				$hash
			);
		}


		/**
		 * Makes sure the required PHP extensions and library versions are all correct
		 *
		 * @static
		 * @access private
		 * @return void
		 */
		static private function verifyPublicKeyEnvironment()
		{
			if (!extension_loaded('openssl')) {
				throw new EnvironmentException(
					'The PHP %s extension is required, however is does not appear to be loaded',
					'openssl'
				);
			}
		}


		/**
		 * Makes sure the required PHP extensions and library versions are all correct
		 *
		 * @static
		 * @access private
		 * @return void
		 */
		static private function verifySymmetricKeyEnvironment()
		{
			if (!extension_loaded('mcrypt')) {
				throw new EnvironmentException(
					'The PHP %s extension is required, however is does not appear to be loaded',
					'mcrypt'
				);
			}

			if (!function_exists('mcrypt_module_open')) {
				throw new EnvironmentException(
					'The cipher used, %1$s (also known as %2$s), requires libmcrypt version 2.4.x or newer. The version installed does not appear to meet this requirement.',
					'AES-192',
					'rijndael-192'
				);
			}

			if (!in_array('rijndael-192', mcrypt_list_algorithms())) {
				throw new EnvironmentException(
					'The cipher used, %1$s (also known as %2$s), does not appear to be supported by the installed version of libmcrypt',
					'AES-192',
					'rijndael-192'
				);
			}
		}


		/**
		 * Build a new cryptographic data object
		 *
		 * @access public
		 * @param string $data The data we're operating on
		 * @return void
		 */
		public function __construct($data) {
			$this->data = $data;
		}


		/**
		 * Checks a password against a hash created with ::hashPassword()
		 *
		 * @access public
		 * @param  string $hash The hash to check against
		 * @return boolean If the password matches the hash
		 */
		public function checkPasswordHash($hash)
		{
			$parts = explode('#', $hash);
			$salt  = isset($parts[1])
				? $parts[1]
				: NULL;

			if (self::hashWithSalt($this->data, $salt) == $hash) {
				return TRUE;
			}

			return FALSE;
		}


		/**
		 * Provides a pure PHP implementation of `hash_hmac()` for when the hash extension is not installed
		 *
		 * @access public
		 * @param  string $type The type of hashing algorithm to use: `'md5'` or `'sha1'`
		 * @param  string $key The key to generate the HMAC with
		 * @return string  The HMAC
		 */
		public function hashHMAC($type, $key)
		{
			if (function_exists('hash_hmac')) {
				return hash_hmac($type, $this->data, $key);
			}

			//
			// Algorithm from http://www.ietf.org/rfc/rfc2104.txt
			//

			if (strlen($key) > 64) {
				$key = pack('H*', $type($key));
			}

			$key  = str_pad($key, 64, "\x0");
			$ipad = str_repeat("\x36", 64);
			$opad = str_repeat("\x5C", 64);

			return $type(($key ^ $opad) . pack('H*', $type(($key ^ $ipad) . $this->data)));
		}


		/**
		 * Hashes a password using a loop of sha1 hashes and a salt, making rainbow table attacks
		 * infeasible.
		 *
		 * @access public
		 * @param string $slat The salt to hash the data with
		 * @return string An 80 character string of the fingerprint, salt and hashed password
		 */
		public function hashPassword($salt = NULL)
		{
			return self::hashWithSalt($this->data, $salt ?: Core::randomString(10));
		}


		/**
		 * Decrypts ciphertext encrypted using public-key encryption via ::publicKeyEncrypt()
		 *
		 * A public key (X.509 certificate) is required for encryption and a
		 * private key (PEM) is required for decryption.
		 *
		 * @access public
		 * @param string $private_key_file The path to a PEM-encoded private key
		 * @param string $password The password for the private key
		 * @return string The decrypted plaintext
		 * @throws ValidationException  When the ciphertext appears to be corrupted
		 */
		public function publicKeyDecrypt($private_key_file, $password = '')
		{
			self::verifyPublicKeyEnvironment();

			$key_resource = self::createPrivateKeyResource($private_key_file, $password);
			$elements     = explode('#', $this->data);

			//
			// We need to make sure this ciphertext came from here, otherwise we are gonna
			// have issues decrypting it
			//

			if (sizeof($elements) != 4 || $elements[0] != __CLASS__ . '::public') {
				throw new ProgrammerException(
					'The ciphertext provided does not appear to have been encrypted using %s',
					__CLASS__ . '::publicKeyEncrypt()'
				);
			}

			$encrypted_key  = base64_decode($elements[1]);
			$unencoded_data = base64_decode($elements[2]);
			$provided_hmac  = $elements[3];
			$plaintext      = '';

			if (!openssl_open($unencoded_data, $plaintext, $encrypted_key, $key_resource)) {
				throw new EnvironmentException(
					'There was an unknown error decrypting the ciphertext provided'
				);

			} else {
				openssl_free_key($key_resource);
			}

			$hmac = new self($encrypted_key . $unencoded_data);

			//
			// By verifying the HMAC we ensure the integrity of the data
			//

			if ($hmac->hashHMAC('sha1', $plaintext) != $provided_hmac) {
				throw new ValidationException(
					'The ciphertext provided appears to have been tampered with or corrupted'
				);
			}

			return $plaintext;
		}


		/**
		 * Encrypts the passed data using public key encryption via OpenSSL
		 *
		 * A public key (X.509 certificate) is required for encryption and a private key (PEM) is
		 * required for decryption.
		 *
		 * @access public
		 * @param string $public_key_file  The path to an X.509 public key certificate
		 * @return string A base-64 encoded result containing a fingerprint and  encrypted data
		 */
		public function publicKeyEncrypt($public_key_file)
		{
			self::verifyPublicKeyEnvironment();

			$key_resource   = self::createPublicKeyResource($public_key_file);
			$ciphertext     = '';
			$encrypted_keys = array();

			if (!openssl_seal($this->data, $ciphertext, $encrypted_keys, array($key_resource))) {
				throw new EnvironmentException(
					'There was an unknown error encrypting the plaintext provided'
				);

			} else {
				openssl_free_key($key_resource);
			}

			$hmac = new self($encrypted_keys[0] . $ciphertext);

			return sprintf(
				'%s::public#%s#%s#%s',
				__CLASS__,
				base64_encode($encrypted_keys[0]),
				base64_encode($ciphertext),
				$hmac->hashHMAC('sha1', $this->data)
			);
		}


		/**
		 * Creates a signature for plaintext to allow verification of the creator
		 *
		 * A private key (PEM) is required for signing and a public key (X.509 certificate) is
		 * required for verification.
		 *
		 * @access public
		 * @param  string $private_key_file The path to a PEM-encoded private key
		 * @param  string $password The password for the private key
		 * @return string The base64-encoded signature
		 * @throws ValidationException  When the private key is invalid
		 */
		public function publicKeySign($private_key_file, $password = '')
		{
			self::verifyPublicKeyEnvironment();

			$key_resource = self::createPrivateKeyResource($private_key_file, $password);

			if (!openssl_sign($this->data, $signature, $key_resource)) {
				throw new EnvironmentException(
					'There was an unknown error signing the data'
				);

			} else {
				openssl_free_key($key_resource);
			}

			return base64_encode($signature);
		}


		/**
		 * Checks a signature for plaintext to verify the creator - works with ::publicKeySign()
		 *
		 * A private key (PEM) is required for signing and a public key
		 * (X.509 certificate) is required for verification.
		 *
		 * @access public
		 * @param string $public_key_file The path to an X.509 public key certificate
		 * @param string $signature The base64-encoded signature for the plaintext
		 * @return boolean If the public key matches the key of the user who signed the data
		 */
		public function publicKeyVerify($public_key_file, $signature)
		{
			self::verifyPublicKeyEnvironment();

			$key_resource = self::createPublicKeyResource($public_key_file);

			switch (openssl_verify($this->data, base64_decode($signature), $key_resource)) {
				case 0:
					openssl_free_key($key_resource);
					return FALSE;

				case 1:
					openssl_free_key($key_resource);
					return TRUE;

				default:
					throw new EnvironmentException(
						'There was an unknown error verifying the data and signature'
					);
			}
		}



























		/**
		 * Decrypts ciphertext encrypted using symmetric-key encryption via ::symmetricKeyEncrypt()
		 *
		 * Since this is symmetric-key cryptography, the same key is used for
		 * encryption and decryption.
		 *
		 * @throws ValidationException  When the ciphertext appears to be corrupted
		 *
		 * @param  string $ciphertext  The content to be decrypted
		 * @param  string $secret_key  The secret key to use for decryption
		 * @return string  The decrypted plaintext
		 */
		static public function symmetricKeyDecrypt($ciphertext, $secret_key)
		{
			self::verifySymmetricKeyEnvironment();

			$elements = explode('#', $ciphertext);

			// We need to make sure this ciphertext came from here, otherwise we are gonna have issues decrypting it
			if (sizeof($elements) != 4 || $elements[0] != __CLASS__ . '::symmetric') {
				throw new ProgrammerException(
					'The ciphertext provided does not appear to have been encrypted using %s',
					__CLASS__ . '::symmetricKeyEncrypt()'
				);
			}

			$iv            = base64_decode($elements[1]);
			$ciphertext    = base64_decode($elements[2]);
			$provided_hmac = $elements[3];

			$hmac = self::hashHMAC('sha1', $iv . '#' . $ciphertext, $secret_key);

			// By verifying the HMAC we ensure the integrity of the data
			if ($hmac != $provided_hmac) {
				throw new ValidationException(
					'The ciphertext provided appears to have been tampered with or corrupted'
				);
			}

			// This code uses the Rijndael cipher with a 192 bit block size and a 256 bit key in cipher feedback mode
			$module   = mcrypt_module_open('rijndael-192', '', 'cfb', '');
			$key      = substr(sha1($secret_key), 0, mcrypt_enc_get_key_size($module));
			mcrypt_generic_init($module, $key, $iv);

			Core::startErrorCapture(E_WARNING);
			$plaintext = mdecrypt_generic($module, $ciphertext);
			Core::stopErrorCapture();

			mcrypt_generic_deinit($module);
			mcrypt_module_close($module);

			return $plaintext;
		}


		/**
		 * Encrypts the passed data using symmetric-key encryption
		 *
		 * Since this is symmetric-key cryptography, the same key is used for
		 * encryption and decryption.
		 *
		 * @throws ValidationException  When the $secret_key is less than 8 characters long
		 *
		 * @param  string $plaintext   The content to be encrypted
		 * @param  string $secret_key  The secret key to use for encryption - must be at least 8 characters
		 * @return string  An encrypted and base-64 encoded result containing a Flourish fingerprint and suitable for decryption using ::symmetricKeyDecrypt()
		 */
		static public function symmetricKeyEncrypt($plaintext, $secret_key)
		{
			if (strlen($secret_key) < 8) {
				throw new ValidationException(
					'The secret key specified does not meet the minimum requirement of being at least %s characters long',
					8
				);
			}

			self::verifySymmetricKeyEnvironment();

			// This code uses the Rijndael cipher with a 192 bit block size and a
			// 256 bit key in cipher feedback mode. Cipher feedback mode is chosen
			// because no extra padding is added, ensuring we always get the exact
			// same plaintext out of the decrypt method
			$module   = mcrypt_module_open('rijndael-192', '', 'cfb', '');
			$key      = substr(sha1($secret_key), 0, mcrypt_enc_get_key_size($module));
			srand();
			$iv       = mcrypt_create_iv(mcrypt_enc_get_iv_size($module), MCRYPT_RAND);

			// Finish the main encryption
			mcrypt_generic_init($module, $key, $iv);

			Core::startErrorCapture(E_WARNING);
			$ciphertext = mcrypt_generic($module, $plaintext);
			Core::stopErrorCapture();

			// Clean up the main encryption
			mcrypt_generic_deinit($module);
			mcrypt_module_close($module);

			// Here we are generating the HMAC for the encrypted data to ensure data integrity
			$hmac = self::hashHMAC('sha1', $iv . '#' . $ciphertext, $secret_key);

			// All of the data is then encoded using base64 to prevent issues with character sets
			$encoded_iv         = base64_encode($iv);
			$encoded_ciphertext = base64_encode($ciphertext);

			// Indicate in the resulting encrypted data what the encryption tool was
			return __CLASS__ . '::symmetric#' . $encoded_iv . '#' . $encoded_ciphertext . '#' . $hmac;
		}
	}
}