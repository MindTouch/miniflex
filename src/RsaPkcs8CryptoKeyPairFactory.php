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
namespace modethirteen\Crypto;

use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;

class RsaPkcs8CryptoKeyPairFactory implements CryptoKeyPairFactoryInterface {

    private string $algo = CryptoKey::DIGEST_ALGORITHM;

    private int $bits = 4096;

    /**
     * {@inheritDoc}
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     */
    public function newCryptoKeyPair(): CryptoKeyPair {

        // generate private key
        $rsa = openssl_pkey_new([
            'digest_alg' => $this->algo,
            'private_key_bits' => $this->bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);
        if($rsa === false) {
            throw new CryptoKeyFactoryCannotConstructCryptoKeyException('failed to generate private key: ' . openssl_error_string());
        }
        $privateKeyText = null;
        openssl_pkey_export($rsa, $privateKeyText);
        if($privateKeyText === null) {
            throw new CryptoKeyFactoryCannotConstructCryptoKeyException('failed to generate private key: ' . openssl_error_string());
        }
        $publicKeyData = openssl_pkey_get_details($rsa);
        if($publicKeyData === false) {
            throw new CryptoKeyFactoryCannotConstructCryptoKeyException('failed to extract public key: ' . openssl_error_string());
        }
        return (new ImportCryptoKeyPairFactory($privateKeyText, $publicKeyData['key'] ?? ''))
            ->withDigestAlgorithm($this->algo)
            ->newCryptoKeyPair();
    }

    /**
     * @param string $algo - key fingerprint/digest algorithm
     * @return static
     */
    public function withDigestAlgorithm(string $algo) : object {
        $instance = clone $this;
        $instance->algo = $algo;
        return $instance;
    }

    /**
     * @param int $bits - key length
     * @return static
     */
    public function withCryptoKeyLength(int $bits) : object {
        $instance = clone $this;
        $instance->bits = $bits;
        return $instance;
    }
}
