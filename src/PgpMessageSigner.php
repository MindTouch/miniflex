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

use gnupg;
use modethirteen\Crypto\Exception\CryptoKeySignerException;
use modethirteen\TypeEx\StringEx;

class PgpMessageSigner implements SignerInterface {

    /**
     * @param CryptoKeyInterface $key - PGP private key
     * @param string $message - message to sign
     */
    public function __construct(private CryptoKeyInterface $key, private string $message)
    {
    }

    /**
     * {@inheritDoc}
     * @throws CryptoKeySignerException
     */
    public function sign() : ?string {
        $fingerprint = $this->key->getFingerprint();
        if(StringEx::isNullOrEmpty($fingerprint)) {
            throw new CryptoKeySignerException($this->key, 'Cannot retrieve PGP private key fingerprint to sign message');
        }
        $gnupg = new gnupg();
        $gnupg->addsignkey($fingerprint);

        // gnupg::sign returns string|bool, but the docblock only declares string (failing static analysis)
        $result = StringEx::stringify($gnupg->sign($this->message));
        return $result !== 'false' ? $result : null;
    }
}
