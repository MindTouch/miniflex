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
use modethirteen\Crypto\Exception\CryptoKeySignerException;

class X509CertificateBuilder {

    private string $algo = CryptoKey::DIGEST_ALGORITHM;

    /**
     * @var array<string, string>
     */
    private array $data = [];

    private int $days = 365;

    private \modethirteen\Crypto\X509CertificateSigner $signature;

    /**
     * @param CryptoKeyInterface $privateKey - RSA private signing key
     */
    public function __construct(CryptoKeyInterface $privateKey) {
        $this->signature = new X509CertificateSigner($privateKey, $this);
    }

    public function getDays() : int {
        return $this->days;
    }

    /**
     * @return array<string, string>
     */
    public function toDistinguishedNamesArray() : array {
        return $this->data;
    }

    /**
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws CryptoKeySignerException
     */
    public function toSignedCryptoKey() : CryptoKeyInterface {
        return (new ImportCryptoKeyFactory($this->signature->sign()))
            ->withDigestAlgorithm($this->algo)
            ->newCryptoKey();
    }

    /**
     * @return static
     */
    public function setDays(int $days) : object {
        $this->days = $days;
        return $this;
    }

    /**
     * @return static
     */
    public function setCommonName(string $name) : object {
        $this->data['commonName'] = $name;
        return $this;
    }

    /**
     * @return static
     */
    public function setDigestAlgorithm(string $algo) : object {
        $this->algo = $algo;
        return $this;
    }

    /**
     * @return static
     */
    public function setEmailAddress(string $email) : object {
        $this->data['emailAddress'] = $email;
        return $this;
    }

    /**
     * @return static
     */
    public function setCountryName(string $name) : object {
        $this->data['countryName'] = $name;
        return $this;
    }

    /**
     * @return static
     */
    public function setLocalityName(string $name) : object {
        $this->data['localityName'] = $name;
        return $this;
    }

    /**
     * @return static
     */
    public function setOrganizationName(string $name) : object {
        $this->data['organizationName'] = $name;
        return $this;
    }

    /**
     * @return static
     */
    public function setOrganizationalUnitName(string $name) : object {
        $this->data['organizationalUnitName'] = $name;
        return $this;
    }

    /**
     * @return static
     */
    public function setStateOrProvinceName(string $name) : object {
        $this->data['stateOrProvinceName'] = $name;
        return $this;
    }
}
