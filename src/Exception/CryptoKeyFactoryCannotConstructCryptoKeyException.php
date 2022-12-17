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
namespace modethirteen\Crypto\Exception;

use Exception;

class CryptoKeyFactoryCannotConstructCryptoKeyException extends Exception {

    private string $error;

    /**
     * @param string $error - the specific error or reason the key pair cannot be instantiated
     */
    public function __construct(string $error) {
        parent::__construct("Cannot construct the cryptographic key pair, {$error}");
        $this->error = $error;
    }

    public function getError() : string {
        return $this->error;
    }
}