# Cryptography
## Provides session-based messaging for page-to-page communication

_Copyright (c) 2007-2015 Will Bond, Matthew J. Sahagian, others_.
_Please reference the LICENSE.md file at the root of this distribution_

#### Namespace

`Dotink\Flourish`

#### Authors

<table>
	<thead>
		<th>Name</th>
		<th>Handle</th>
		<th>Email</th>
	</thead>
	<tbody>
	
		<tr>
			<td>
				Will Bond
			</td>
			<td>
				wb
			</td>
			<td>
				will@flourishlib.com
			</td>
		</tr>
	
		<tr>
			<td>
				Matthew J. Sahagian
			</td>
			<td>
				mjs
			</td>
			<td>
				msahagian@dotink.org
			</td>
		</tr>
	
	</tbody>
</table>

## Properties

### Instance Properties
#### <span style="color:#6a6e3d;">$data</span>

The data we're working with




## Methods
### Static Methods
<hr />

#### <span style="color:#3e6a6e;">createPrivateKeyResource()</span>

Create a private key resource based on a filename and password

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$private_key_file
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The path to a PEM-encoded private key
			</td>
		</tr>
					
		<tr>
			<td>
				$password
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The password for the private key
			</td>
		</tr>
			
	</tbody>
</table>

###### Throws

<dl>

	<dt>
					Dotink\Flourish\ValidationException		
	</dt>
	<dd>
		When the private key is invalid
	</dd>

</dl>

###### Returns

<dl>
	
		<dt>
			resource
		</dt>
		<dd>
			The private key resource
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">createPublicKeyResource()</span>

Create a public key resource based on a filename

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$public_key_file
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The path to an X.509 public key certificate
			</td>
		</tr>
			
	</tbody>
</table>

###### Returns

<dl>
	
		<dt>
			resource
		</dt>
		<dd>
			The public key resource
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">hashWithSalt()</span>

Performs a large iteration of hashing a string with a salt

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$source
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The string to hash
			</td>
		</tr>
					
		<tr>
			<td>
				$salt
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The salt for the hash
			</td>
		</tr>
			
	</tbody>
</table>

###### Returns

<dl>
	
		<dt>
			string
		</dt>
		<dd>
			An 80 character string of the Flourish fingerprint, salt and hashed password
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">verifyPublicKeyEnvironment()</span>

Makes sure the required PHP extensions and library versions are all correct

###### Returns

<dl>
	
		<dt>
			void
		</dt>
		<dd>
			Provides no return value.
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">verifySymmetricKeyEnvironment()</span>

Makes sure the required PHP extensions and library versions are all correct

###### Returns

<dl>
	
		<dt>
			void
		</dt>
		<dd>
			Provides no return value.
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">symmetricKeyDecrypt()</span>

Decrypts ciphertext encrypted using symmetric-key encryption via ::symmetricKeyEncrypt()

##### Details

Since this is symmetric-key cryptography, the same key is used for
encryption and decryption.

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$ciphertext
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The content to be decrypted
			</td>
		</tr>
					
		<tr>
			<td>
				$secret_key
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The secret key to use for decryption
			</td>
		</tr>
			
	</tbody>
</table>

###### Throws

<dl>

	<dt>
					Dotink\Flourish\ValidationException		
	</dt>
	<dd>
		When the ciphertext appears to be corrupted
	</dd>

</dl>

###### Returns

<dl>
	
		<dt>
			string
		</dt>
		<dd>
			The decrypted plaintext
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">symmetricKeyEncrypt()</span>

Encrypts the passed data using symmetric-key encryption

##### Details

Since this is symmetric-key cryptography, the same key is used for
encryption and decryption.

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$plaintext
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The content to be encrypted
			</td>
		</tr>
					
		<tr>
			<td>
				$secret_key
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The secret key to use for encryption - must be at least 8 characters
			</td>
		</tr>
			
	</tbody>
</table>

###### Throws

<dl>

	<dt>
					Dotink\Flourish\ValidationException		
	</dt>
	<dd>
		When the $secret_key is less than 8 characters long
	</dd>

</dl>

###### Returns

<dl>
	
		<dt>
			string
		</dt>
		<dd>
			An encrypted and base-64 encoded result containing a Flourish fingerprint and suitable for decryption using ::symmetricKeyDecrypt()
		</dd>
	
</dl>




### Instance Methods
<hr />

#### <span style="color:#3e6a6e;">__construct()</span>

Build a new cryptographic data object

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$data
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The data we're operating on
			</td>
		</tr>
			
	</tbody>
</table>

###### Returns

<dl>
	
		<dt>
			void
		</dt>
		<dd>
			Provides no return value.
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">checkPasswordHash()</span>

Checks a password against a hash created with ::hashPassword()

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$hash
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The hash to check against
			</td>
		</tr>
			
	</tbody>
</table>

###### Returns

<dl>
	
		<dt>
			boolean
		</dt>
		<dd>
			If the password matches the hash
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">hashHMAC()</span>

Provides a pure PHP implementation of `hash_hmac()` for when the hash extension is not installed

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$type
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The type of hashing algorithm to use: `'md5'` or `'sha1'`
			</td>
		</tr>
					
		<tr>
			<td>
				$key
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The key to generate the HMAC with
			</td>
		</tr>
			
	</tbody>
</table>

###### Returns

<dl>
	
		<dt>
			string
		</dt>
		<dd>
			The HMAC
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">hashPassword()</span>

Hashes a password using a loop of sha1 hashes and a salt, making rainbow table attacks
infeasible.

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$slat
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The salt to hash the data with
			</td>
		</tr>
			
	</tbody>
</table>

###### Returns

<dl>
	
		<dt>
			string
		</dt>
		<dd>
			An 80 character string of the fingerprint, salt and hashed password
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">publicKeyDecrypt()</span>

Decrypts ciphertext encrypted using public-key encryption via ::publicKeyEncrypt()

##### Details

A public key (X.509 certificate) is required for encryption and a
private key (PEM) is required for decryption.

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$private_key_file
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The path to a PEM-encoded private key
			</td>
		</tr>
					
		<tr>
			<td>
				$password
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The password for the private key
			</td>
		</tr>
			
	</tbody>
</table>

###### Throws

<dl>

	<dt>
					Dotink\Flourish\ValidationException		
	</dt>
	<dd>
		When the ciphertext appears to be corrupted
	</dd>

</dl>

###### Returns

<dl>
	
		<dt>
			string
		</dt>
		<dd>
			The decrypted plaintext
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">publicKeyEncrypt()</span>

Encrypts the passed data using public key encryption via OpenSSL

##### Details

A public key (X.509 certificate) is required for encryption and a private key (PEM) is
required for decryption.

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$public_key_file
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The path to an X.509 public key certificate
			</td>
		</tr>
			
	</tbody>
</table>

###### Returns

<dl>
	
		<dt>
			string
		</dt>
		<dd>
			A base-64 encoded result containing a fingerprint and  encrypted data
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">publicKeySign()</span>

Creates a signature for plaintext to allow verification of the creator

##### Details

A private key (PEM) is required for signing and a public key (X.509 certificate) is
required for verification.

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$private_key_file
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The path to a PEM-encoded private key
			</td>
		</tr>
					
		<tr>
			<td>
				$password
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The password for the private key
			</td>
		</tr>
			
	</tbody>
</table>

###### Throws

<dl>

	<dt>
					Dotink\Flourish\ValidationException		
	</dt>
	<dd>
		When the private key is invalid
	</dd>

</dl>

###### Returns

<dl>
	
		<dt>
			string
		</dt>
		<dd>
			The base64-encoded signature
		</dd>
	
</dl>


<hr />

#### <span style="color:#3e6a6e;">publicKeyVerify()</span>

Checks a signature for plaintext to verify the creator - works with ::publicKeySign()

##### Details

A private key (PEM) is required for signing and a public key
(X.509 certificate) is required for verification.

###### Parameters

<table>
	<thead>
		<th>Name</th>
		<th>Type(s)</th>
		<th>Description</th>
	</thead>
	<tbody>
			
		<tr>
			<td>
				$public_key_file
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The path to an X.509 public key certificate
			</td>
		</tr>
					
		<tr>
			<td>
				$signature
			</td>
			<td>
									<a href="http://php.net/language.types.string">string</a>
				
			</td>
			<td>
				The base64-encoded signature for the plaintext
			</td>
		</tr>
			
	</tbody>
</table>

###### Returns

<dl>
	
		<dt>
			boolean
		</dt>
		<dd>
			If the public key matches the key of the user who signed the data
		</dd>
	
</dl>






