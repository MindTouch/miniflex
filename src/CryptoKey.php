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
use modethirteen\TypeEx\StringEx;

class CryptoKey implements CryptoKeyInterface, \Stringable {
    public const DIGEST_ALGORITHM = 'sha256';
    public const FORMAT_CERTIFICATE = 'CERTIFICATE';
    public const FORMAT_PGP_PRIVATE_KEY_BLOCK = 'PGP PRIVATE KEY BLOCK';
    public const FORMAT_PGP_PUBLIC_KEY_BLOCK = 'PGP PUBLIC KEY BLOCK';
    public const FORMAT_PRIVATE_KEY = 'PRIVATE KEY';
    public const FORMAT_PUBLIC_KEY = 'PUBLIC KEY';
    public const FORMAT_RSA_PRIVATE_KEY = 'RSA PRIVATE KEY';
    public const FORMAT_RSA_PUBLIC_KEY = 'RSA PUBLIC KEY';

    /**
     * @var string[]
     */
    private static array $supportedFormats = [
        self::FORMAT_CERTIFICATE,
        self::FORMAT_PGP_PRIVATE_KEY_BLOCK,
        self::FORMAT_PGP_PUBLIC_KEY_BLOCK,
        self::FORMAT_PRIVATE_KEY,
        self::FORMAT_PUBLIC_KEY,
        self::FORMAT_RSA_PRIVATE_KEY,
        self::FORMAT_RSA_PUBLIC_KEY
    ];

    /**
     * @param string $format - PEM key block format (CERTIFICATE, PGP PUBLIC KEY BLOCK, ...)
     */
    public static function isSupportedCryptoKeyFormat(string $format) : bool {
        return in_array($format, self::$supportedFormats);
    }


    /**
     * Add PEM headers and whitespace
     *
     * @param string $text - PEM key block with or without headers
     * @param string $format - key block format (CERTIFICATE, PGP PUBLIC KEY BLOCK, ...)
     */
    public static function pem(string $text, string $format) : string {
        return self::_pem(self::trim($text), $format);
    }

    /**
     * Remove PEM headers and whitespace
     *
     * @param string $text - PEM key block
     */
    public static function trim(string $text) : string {
        $text = str_replace(["\x0D", "\r", "\n"], '', $text);
        if(!StringEx::isNullOrEmpty($text)) {
            $text = preg_replace('/-----(BEGIN|END) .+?-----/', '', $text);
            $text = str_replace(' ', '', $text);
        }
        return $text;
    }

    /**
     * Add PEM headers and whitespace (internal helper skips trimming PEM key block)
     *
     * @param string $text - PEM key block without headers
     * @param string $format - PEM key block format (CERTIFICATE, PGP PUBLIC KEY BLOCK, ...)
     */
    private static function _pem(string $text, string $format) : string {

        /** @noinspection PhpRedundantOptionalArgumentInspection */
        return "-----BEGIN {$format}-----\n" . chunk_split($text, 64, "\n") . "-----END {$format}-----\n";
    }

    private ?int $expiration = null;

    private ?string $fingerprint = null;

    /**
     * @var string
     */
    private $format;

    private string $pem;

    private ?string $name = null;

    private string $text;

    /**
     * @param string $text - PEM key block
     * @param Closure $formatHandler - <$formatHandler(string $text) : string> : handle PEM key block format when unable to infer from PEM key block
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     */
    public function __construct(string $text, Closure $formatHandler) {
        if(preg_match('/-----BEGIN (.+?)-----/', $text, $matches)) {
            $this->format = $matches[1] ?? null;
        } else {
            $this->format = $formatHandler($text);
        }
        if(!self::isSupportedCryptoKeyFormat($this->format)) {
            throw new CryptoKeyCannotParseCryptoKeyTextException('invalid key block format', $text);
        }
        $this->text = self::trim($text);
        $this->pem = self::_pem($this->text, $this->format);
    }

    public function __toString() : string {
        return $this->toString();
    }

    public function getExpiration() : ?int {
        return $this->expiration;
    }

    public function getFingerprint() : ?string {
        return $this->fingerprint;
    }

    public function getName() : ?string {
        return $this->name;
    }

    public function getFormat() : string {
        return $this->format;
    }

    public function is(string $type) : bool {
        return $type === $this->format;
    }

    public function toString() : string {
        return $this->pem;
    }

    public function toText() : string {
        return $this->text;
    }

    /**
     * @return static
     */
    public function withExpiration(int $expiration) : object {
        $key = clone $this;
        $key->expiration = $expiration;
        return $key;
    }

    /**
     * @return static
     */
    public function withFingerprint(string $fingerprint) : object {
        $key = clone $this;
        $key->fingerprint = $fingerprint;
        return $key;
    }

    /**
     * @return static
     */
    public function withName(string $name) : object {
        $key = clone $this;
        $key->name = $name;
        return $key;
    }
}
