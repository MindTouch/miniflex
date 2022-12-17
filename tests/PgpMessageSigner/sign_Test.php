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
namespace modethirteen\Crypto\Tests\PgpMessageSigner;

use gnupg;
use modethirteen\Crypto\CryptoKey;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Crypto\Exception\CryptoKeySignerException;
use modethirteen\Crypto\ImportCryptoKeyFactory;
use modethirteen\Crypto\ImportCryptoKeyPairFactory;
use modethirteen\Crypto\PgpMessageSigner;
use modethirteen\Crypto\Tests\AbstractCryptoTestCase;

class sign_Test extends AbstractCryptoTestCase {

    /**
     * @test
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     */
    public function Can_handle_no_PGP_fingerprint() : void {

        // assert
        static::expectException(CryptoKeySignerException::class);

        // arrange
        $key = (new ImportCryptoKeyFactory(self::getPgpPrivateKeyText()))
            ->newCryptoKey();
        if($key instanceof CryptoKey) {
            $key = $key->withFingerprint('');
        }
        $signature = new PgpMessageSigner($key, 'foo');

        // act
        $signature->sign();
    }

    /**
     * @test
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeySignerException
     */
    public function Can_get_message_signed_with_private_pgp() : void {

        // arrange
        $pair = (new ImportCryptoKeyPairFactory(self::getPgpPrivateKeyText(), self::getPgpPublicKeyText()))
            ->newCryptoKeyPair();
        $message = <<<TEXT
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
TEXT;
        $signature = new PgpMessageSigner($pair->getPrivateKey(), $message);

        // act
        $result = $signature->sign();

        // assert
        $results = (new gnupg())->verify($result, false);
        if(!is_array($results)) {
            static::fail('Cannot verify signed message');
        }
        $fingerprints = array_map(fn(array $result) => $result['fingerprint'] ?? null, $results);
        $fingerprints = array_filter($fingerprints, 'strlen');
        if(!in_array($pair->getPublicKey()->getFingerprint(), $fingerprints)) {
            static::fail('Cannot find PGP public key fingerprint in message signature');
        } else {
            static::addToAssertionCount(1);
        }
    }
}
