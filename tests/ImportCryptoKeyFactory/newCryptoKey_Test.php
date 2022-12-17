<?php declare(strict_types=1);
/**
 * modethirteen/miniflex
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace modethirteen\Crypto\Tests\ImportCryptoKeyFactory;

use modethirteen\Crypto\CryptoKey;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Crypto\ImportCryptoKeyFactory;
use modethirteen\Crypto\Tests\AbstractCryptoTestCase;

class newCryptoKey_Test extends AbstractCryptoTestCase {

    public static function text_format_algo_expectedFormat_expectedFingerprint_expectedExpiration_expectedName_Provider() : array {
        return [
            'RSA PKCS #1 private key' => [
                self::getRsaPkcs1PrivateKeyText(),
                null,
                null,
                CryptoKey::FORMAT_RSA_PRIVATE_KEY,
                null,
                null,
                null
            ],
            'RSA PKCS #1 private key without header' => [
                CryptoKey::trim(self::getRsaPkcs1PrivateKeyText()),
                CryptoKey::FORMAT_RSA_PRIVATE_KEY,
                null,
                CryptoKey::FORMAT_RSA_PRIVATE_KEY,
                null,
                null,
                null
            ],
            'RSA PKCS #1 public key' => [
                self::getRsaPkcs1PublicKeyText(),
                null,
                null,
                CryptoKey::FORMAT_RSA_PUBLIC_KEY,
                null,
                null,
                null
            ],
            'RSA PKCS #1 public key without header' => [
                CryptoKey::trim(self::getRsaPkcs1PublicKeyText()),
                CryptoKey::FORMAT_RSA_PUBLIC_KEY,
                null,
                CryptoKey::FORMAT_RSA_PUBLIC_KEY,
                null,
                null,
                null
            ],
            'RSA PKCS #8 private key' => [
                self::getRsaPkcs8PrivateKeyText(),
                null,
                null,
                CryptoKey::FORMAT_PRIVATE_KEY,
                null,
                null,
                null
            ],
            'RSA PKCS #8 private key without header' => [
                CryptoKey::trim(self::getRsaPkcs8PrivateKeyText()),
                CryptoKey::FORMAT_PRIVATE_KEY,
                null,
                CryptoKey::FORMAT_PRIVATE_KEY,
                null,
                null,
                null
            ],
            'RSA PKCS #8 public key' => [
                self::getRsaPkcs8PublicKeyText(),
                null,
                null,
                CryptoKey::FORMAT_PUBLIC_KEY,
                null,
                null,
                null
            ],
            'RSA PKCS #8 public key without header' => [
                CryptoKey::trim(self::getRsaPkcs8PublicKeyText()),
                CryptoKey::FORMAT_PUBLIC_KEY,
                null,
                CryptoKey::FORMAT_PUBLIC_KEY,
                null,
                null,
                null
            ],
            'PGP private key' => [
                self::getPgpPrivateKeyText(),
                null,
                null,
                CryptoKey::FORMAT_PGP_PRIVATE_KEY_BLOCK,
                '1C63627584B38D8E3DE257C397A625C6D8C7C8F6',
                null,
                null
            ],
            'PGP private key without header' => [
                CryptoKey::trim(self::getPgpPrivateKeyText()),
                CryptoKey::FORMAT_PGP_PRIVATE_KEY_BLOCK,
                null,
                CryptoKey::FORMAT_PGP_PRIVATE_KEY_BLOCK,
                '1C63627584B38D8E3DE257C397A625C6D8C7C8F6',
                null,
                null
            ],
            'PGP public key' => [
                self::getPgpPublicKeyText(),
                null,
                null,
                CryptoKey::FORMAT_PGP_PUBLIC_KEY_BLOCK,
                '1C63627584B38D8E3DE257C397A625C6D8C7C8F6',
                null,
                null
            ],
            'PGP public key without header' => [
                CryptoKey::trim(self::getPgpPublicKeyText()),
                CryptoKey::FORMAT_PGP_PUBLIC_KEY_BLOCK,
                null,
                CryptoKey::FORMAT_PGP_PUBLIC_KEY_BLOCK,
                '1C63627584B38D8E3DE257C397A625C6D8C7C8F6',
                null,
                null
            ],
            'x.509 certificate' => [
                self::getX509CertificateKeyText(),
                null,
                null,
                CryptoKey::FORMAT_CERTIFICATE,
                '6c45f005b55637699ddce74371d57908e08bcecdc3c910d5d7817ee9c8b33546',
                1_612_841_998,
                '_C=CA_ST=xyzzy_L=plugh_O=foo_OU=bar_CN=baz_emailAddress=qux@example.com'
            ],
            'x.509 certificate without header' => [
                CryptoKey::trim(self::getX509CertificateKeyText()),
                CryptoKey::FORMAT_CERTIFICATE,
                null,
                CryptoKey::FORMAT_CERTIFICATE,
                '6c45f005b55637699ddce74371d57908e08bcecdc3c910d5d7817ee9c8b33546',
                1_612_841_998,
                '_C=CA_ST=xyzzy_L=plugh_O=foo_OU=bar_CN=baz_emailAddress=qux@example.com'
            ],
            'x.509 certificate with sha512 digest algorithm' => [
                self::getX509CertificateKeyText(),
                null,
                'sha512',
                CryptoKey::FORMAT_CERTIFICATE,
                '2e7450f6409b6c9551a79fe682279d9658de8e736c7d3aa2f9ad1765b907607e943e244280f1d0a9e1db56f5ffefba74fbd76526585fd126f6e932c308be8367',
                1_612_841_998,
                '_C=CA_ST=xyzzy_L=plugh_O=foo_OU=bar_CN=baz_emailAddress=qux@example.com'
            ]
        ];
    }

    /**
     * @dataProvider text_format_algo_expectedFormat_expectedFingerprint_expectedExpiration_expectedName_Provider
     * @test
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     */
    public function Can_get_key(
        string $text,
        ?string $format,
        ?string $algo,
        string $expectedFormat,
        ?string $expectedFingerprint,
        ?string $expectedExpiration,
        ?string $expectedName
    ) : void {

        // arrange
        $factory = new ImportCryptoKeyFactory($text);
        if($format !== null) {
            $factory = $factory->withFormatHandler(fn(): string => $format);
        }
        if($algo !== null) {
            $factory = $factory->withDigestAlgorithm($algo);
        }

        // act
        $key = $factory->newCryptoKey();

        // assert
        static::assertEquals(CryptoKey::trim($text), $key->toText());
        static::assertEquals(CryptoKey::pem($text, $key->getFormat()), $key->toString());
        static::assertEquals($expectedFormat, $key->getFormat());
        static::assertEquals($expectedFingerprint, $key->getFingerprint());
        static::assertEquals($expectedExpiration, $key->getExpiration());
        static::assertEquals($expectedName, $key->getName());
    }
}
