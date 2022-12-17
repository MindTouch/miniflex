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
use gnupg;
use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryMissingFormatException;
use modethirteen\TypeEx\StringEx;

class ImportCryptoKeyFactory implements CryptoKeyFactoryInterface {

    private string $algo = CryptoKey::DIGEST_ALGORITHM;

    /**
     * @var Closure
     */
    private $formatHandler;

    /**
     * @param string $text - PEM key block
     */
    public function __construct(private string $text) {
        $this->formatHandler = function(string $text) {
            throw new CryptoKeyFactoryMissingFormatException($text);
        };
    }

    /**
     * {@inheritDoc}
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     */
    public function newCryptoKey() : CryptoKeyInterface {
        $key = new CryptoKey($this->text, $this->formatHandler);
        switch($key->getFormat()) {
            case CryptoKey::FORMAT_CERTIFICATE:
                $certificate = openssl_x509_read($key->toString());
                if($certificate === false) {
                    throw new CryptoKeyFactoryCannotConstructCryptoKeyException('cryptographic key block could not be imported as an x.509 certificate');
                }
                $data = openssl_x509_parse($certificate);
                $data = is_array($data) ? $data : [];
                if(isset($data['name'])) {
                    $name = str_replace(['/', ' '], ['_', ''], $data['name']);
                    if(!StringEx::isNullOrEmpty($name)) {
                        $key = $key->withName($name);
                    }
                }
                if(isset($data['validTo_time_t'])) {
                    $key = $key->withExpiration(intval($data['validTo_time_t']));
                }
                $fingerprint = openssl_x509_fingerprint($certificate, $this->algo);
                if(!is_bool($fingerprint)) {
                    $key = $key->withFingerprint($fingerprint);
                }
                openssl_x509_free($certificate);
                return $key;
            case CryptoKey::FORMAT_PGP_PRIVATE_KEY_BLOCK:
            case CryptoKey::FORMAT_PGP_PUBLIC_KEY_BLOCK:

                // TODO (modethirteen, 20200616): use custom fingerprint algo in key fingerprints/digests, include expiration
                $data = (new gnupg())->import($key->toString());
                if(!is_array($data)) {
                    throw new CryptoKeyFactoryCannotConstructCryptoKeyException('cryptographic key block could not be imported as GPG/PGP');
                }
                if(isset($data['fingerprint'])) {
                    $key = $key->withFingerprint($data['fingerprint']);
                }
                return $key;
            case CryptoKey::FORMAT_PRIVATE_KEY:
            case CryptoKey::FORMAT_PUBLIC_KEY:
            case CryptoKey::FORMAT_RSA_PRIVATE_KEY:
            case CryptoKey::FORMAT_RSA_PUBLIC_KEY:

                // TODO (modethirteen, 20210109): use custom fingerprint algo in key fingerprints/digests, include expiration, differentiate between PKCS#1 and PCKS#8
                return $key;
            default:
                throw new CryptoKeyFactoryCannotConstructCryptoKeyException('unsupported key format ' . $key->getFormat());
        }
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