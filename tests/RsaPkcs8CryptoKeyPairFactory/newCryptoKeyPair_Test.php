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
namespace modethirteen\Crypto\Tests\RsaPkcs8CryptoKeyPairFactory;

use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Crypto\RsaPkcs8CryptoKeyPairFactory;
use modethirteen\Crypto\Tests\AbstractCryptoTestCase;

class newCryptoKeyPair_Test extends AbstractCryptoTestCase {

    public static function bits_algo_Provider() : array {
        return [
            [null, null],
            [1024, null],
            [2048, 'sha1'],
            [4096, 'sha256'],
            [4096, 'sha512']
        ];
    }

    /**
     * @dataProvider bits_algo_Provider
     * @test
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     */
    public function Can_get_matching_RSA_key_pair(?int $bits, ?string $algo) : void {

        // arrange
        $factory = new RsaPkcs8CryptoKeyPairFactory();
        if($bits !== null) {
            $factory = $factory->withCryptoKeyLength($bits);
        }
        if($algo !== null) {
            $factory = $factory->withDigestAlgorithm($algo);
        }

        // act
        $pair = $factory->newCryptoKeyPair();

        // assert
        static::assertTrue(openssl_sign('foo', $signature, openssl_pkey_get_private($pair->getPrivateKey()->toString())));
        static::assertEquals(1, openssl_verify('foo', $signature, openssl_pkey_get_public($pair->getPublicKey()->toString())));
    }
}
