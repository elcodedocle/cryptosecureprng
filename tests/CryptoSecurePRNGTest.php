<?php

use PHPUnit\Framework\TestCase;
use synapp\info\tools\passwordgenerator\cryptosecureprng\CryptoSecurePRNG;

class CryptoSecurePRNGTest extends TestCase
{
    public function testConstructorDefaults()
    {
        $prng = new CryptoSecurePRNG();
        $this->assertEquals(PHP_INT_SIZE, $prng->getIntByteCount());
        $this->assertEquals(mt_getrandmax(), $prng->getDefaultMax());
    }

    public function testConstructorWithParameters()
    {
        if (!function_exists('mcrypt_create_iv') || !function_exists('openssl_random_pseudo_bytes')) {
            $this->expectException(Exception::class);
        }
        $prng = new CryptoSecurePRNG(2, 100, true, true, true);
        $this->assertEquals(2, $prng->getIntByteCount());
        $this->assertEquals(100, $prng->getDefaultMax());
        $this->assertTrue($prng->getMcrypt());
        $this->assertTrue($prng->getOpenssl());
        $this->assertTrue($prng->getUrandom());
    }

    public function testSetIntByteCountValid()
    {
        $prng = new CryptoSecurePRNG();
        $prng->setIntByteCount(2);
        $this->assertEquals(2, $prng->getIntByteCount());
    }

    public function testSetIntByteCountInvalid()
    {
        $this->expectException(Exception::class);
        $prng = new CryptoSecurePRNG();
        $prng->setIntByteCount(0);
    }

    public function testSetDefaultMaxValid()
    {
        $prng = new CryptoSecurePRNG();
        $prng->setDefaultMax(100);
        $this->assertEquals(100, $prng->getDefaultMax());
    }

    public function testSetDefaultMaxInvalid()
    {
        $this->expectException(Exception::class);
        $prng = new CryptoSecurePRNG();
        $prng->setDefaultMax('not an integer');
    }

    public function testSetFlagMcryptValid()
    {
        $prng = new CryptoSecurePRNG();
        if (function_exists('mcrypt_create_iv')) {
            $prng->setFlag('mcrypt', true);
            $this->assertTrue($prng->getMcrypt());
        } else {
            $this->expectException(Exception::class);
            $prng->setFlag('mcrypt', true);
            $this->assertFalse($prng->getMcrypt());
        }
    }

    public function testSetFlagOpensslValid()
    {
        $prng = new CryptoSecurePRNG();
        $prng->setFlag('openssl', true);
        $this->assertTrue($prng->getOpenssl());
    }

    public function testSetFlagInvalid()
    {
        $this->expectException(Exception::class);
        $prng = new CryptoSecurePRNG();
        $prng->setFlag('invalidflag');
    }

    public function testSetFlagInvalidValue()
    {
        $this->expectException(Exception::class);
        $prng = new CryptoSecurePRNG();
        $prng->setFlag('mcrypt', 'not boolean or null');
    }

    public function testSetUrandomValid()
    {
        $prng = new CryptoSecurePRNG();
        $prng->setUrandom(true);
        $this->assertTrue($prng->getUrandom());
    }

    public function testSetUrandomInvalid()
    {
        $this->expectException(Exception::class);
        $prng = new CryptoSecurePRNG();
        $prng->setUrandom('invalid');
    }

    public function testGetRandomBytesString()
    {
        $prng = new CryptoSecurePRNG(PHP_INT_SIZE, mt_getrandmax(), false, false, true);
        $randomBytes = $prng->getRandomBytesString(16);
        $this->assertEquals(16, strlen($randomBytes));
    }

    public function testGetRandomBytesStringFailure()
    {
        $this->expectException(Exception::class);
        $prng = new CryptoSecurePRNG(PHP_INT_SIZE, mt_getrandmax(), false, false, false, false);
        $prng->getRandomBytesString(16);
    }

    public function testRandWithValidRange()
    {
        $prng = new CryptoSecurePRNG(PHP_INT_SIZE, mt_getrandmax(), false, false, true);
        $rand = $prng->rand(1, 10);
        $this->assertGreaterThanOrEqual(1, $rand);
        $this->assertLessThanOrEqual(10, $rand);
    }

    public function testRandWithMinEqualsMax()
    {
        $prng = new CryptoSecurePRNG();
        $rand = $prng->rand(5, 5);
        $this->assertEquals(5, $rand);
    }

    public function testRandWithInvalidRange()
    {
        $this->expectException(Exception::class);
        $prng = new CryptoSecurePRNG();
        $prng->rand(10, 5);
    }

    public function testRandWithNonInteger()
    {
        $this->expectException(Exception::class);
        $prng = new CryptoSecurePRNG();
        $prng->rand(1, 'invalid');
    }

    public function testDestructor()
    {
        $prng = new CryptoSecurePRNG(PHP_INT_SIZE, mt_getrandmax(), false, false, true);
        unset($prng); // Triggering the destructor by unsetting the object
        $this->assertTrue(true); // Just ensuring the destructor doesn't throw any error
    }
}
