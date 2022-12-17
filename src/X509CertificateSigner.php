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

use modethirteen\Crypto\Exception\CryptoKeySignerException;

class X509CertificateSigner implements SignerInterface {

    /**
     * @param CryptoKeyInterface $privateKey - RSA private signing key
     * @param X509CertificateBuilder $x509 - certificate distinguished names builder
     * @param string $algo - digest algorithm
     */
    public function __construct(private CryptoKeyInterface $privateKey, private X509CertificateBuilder $x509, private string $algo = CryptoKey::DIGEST_ALGORITHM)
    {
    }

    /**
     * {@inheritDoc}
     * @throws CryptoKeySignerException
     */
    public function sign() : ?string {
        $key = openssl_pkey_get_private($this->privateKey->toString());
        if($key === false) {
            throw new CryptoKeySignerException($this->privateKey, 'Cannot load private key: ' . openssl_error_string());
        }
        $csr = openssl_csr_new($this->x509->toDistinguishedNamesArray(), $key, [
            'digest_alg' => $this->algo
        ]);
        if($csr === false) {
            throw new CryptoKeySignerException($this->privateKey, 'Cannot generate certificate signing request: ' . openssl_error_string());
        }

        // TODO (modethirteen, 20200109): add option for signing with CA certificate
        $certificate = openssl_csr_sign($csr, null, $key, $this->x509->getDays(), [
            'digest_alg' => $this->algo
        ]);
        if($certificate === false) {
            throw new CryptoKeySignerException($this->privateKey, 'Cannot sign certificate: ' . openssl_error_string());
        }
        $text = null;
        openssl_x509_export($certificate, $text);
        return $text;
    }
}
