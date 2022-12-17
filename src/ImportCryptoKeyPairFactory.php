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

use Closure;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryMissingFormatException;

class ImportCryptoKeyPairFactory implements CryptoKeyPairFactoryInterface {

    private string $algo = CryptoKey::DIGEST_ALGORITHM;

    /**
     * @var Closure
     */
    private $formatHandler;

    /**
     * @param string $privateKeyText - PEM private key block
     * @param string $publicKeyText - PEM public key block
     */
    public function __construct(private string $privateKeyText, private string $publicKeyText) {
        $this->formatHandler = function(string $text) {
            throw new CryptoKeyFactoryMissingFormatException($text);
        };
    }

    /**
     * {@inheritDoc}
     * @TODO (modethirteen, 20200616): validate key/pair relationships
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     */
    public function newCryptoKeyPair(): CryptoKeyPair {
        return new CryptoKeyPair(
            (new ImportCryptoKeyFactory($this->privateKeyText))
                ->withDigestAlgorithm($this->algo)
                ->withFormatHandler($this->formatHandler)
                ->newCryptoKey(),
            (new ImportCryptoKeyFactory($this->publicKeyText))
                ->withDigestAlgorithm($this->algo)
                ->withFormatHandler($this->formatHandler)
                ->newCryptoKey()
        );
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
     * @param Closure $formatHandler - <$formatHandler(string $text) : string> : handle PEM key block format when unable to infer from PEM key block
     * @return static
     */
    public function withFormatHandler(Closure $formatHandler) : object {
        $instance = clone $this;
        $instance->formatHandler = $formatHandler;
        return $instance;
    }
}
