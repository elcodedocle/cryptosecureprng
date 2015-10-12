<?php
/**
 * Crypto Secure PRNG
 * @copyright Gael Abadin (elcodedocle) 2014
 * @license MIT Expat (http://en.wikipedia.org/wiki/Expat_License)
 * @version 0.2.1-beta
 */

namespace synapp\info\tools\passwordgenerator\cryptosecureprng; //comment this line for PHP<5.3 compat
use Exception; //comment this line for PHP<5.3 compat

/**
 * Class CryptoSecurePRNG
 * 
 * Generates crypto safe byte strings and ints from a given range
 *
 * This class, generates crypto safe byte strings (in fact only a wrapper for using the best method available) 
 * and ints  from a given range (like mt_rand(), but in a safe way. This is the interesting part!)
 * 
 * it uses mcrypt extensions if available, falling back to openssl if available, and falling back to /dev/urandom 
 * if available. It requires PHP 5.3 or higher for two reasons: namespaces, and the use of MCRYPT_DEV_URANDOM as device
 * on mcrypt extension mcrypt_create_iv call, which is not available in windows prior to PHP 5.3 
 * 
 * for all the moderately paranoid fellas out there
 * 
 * @package synapp\info\tools\passwordgenerator\cryptosecureprng
 */
class CryptoSecurePRNG {
    /**
     * @var int stores the size of an int in bytes
     */
    private $intByteCount;
    /**
     * @var int stores the default max value for the random integer generator
     */
    private $defaultMax;
    /**
     * @var bool whether or not mcrypt is available
     */
    private $mcrypt;
    /**
     * @var bool whether or not openssl is available
     */
    private $openssl;
    /**
     * @var bool whether or not urandom is available
     */
    private $urandom;
    /**
     * @var resource file handler for /dev/urandom
     */
    private $urandomFileHandler;

    /**
     * @param int $defaultMax
     * @throws Exception an Exception containing an error message
     */
    public function setDefaultMax($defaultMax)
    {
        if (is_int($defaultMax)){
            $this->defaultMax = $defaultMax;
        } else {
            throw new Exception('Construct parameter $defaultMax must be an integer.');
        }
    }

    /**
     * @return int
     */
    public function getDefaultMax()
    {
        return $this->defaultMax;
    }

    /**
     * @param int $intByteCount
     * @throws Exception an Exception containing an error message
     */
    public function setIntByteCount($intByteCount)
    {
        if (is_int($intByteCount)&&$intByteCount>0){
            $this->intByteCount = $intByteCount;
        } else {
            throw new Exception('Construct parameter $intByteCount must be an integer > 0.');
        }
    }

    /**
     * @return int
     */
    public function getIntByteCount()
    {
        return $this->intByteCount;
    }

    /**
     * @param string $flag 'mcrypt' or 'openssl'
     * @param boolean $value (optional, null for default)
     * @throws \Exception
     */
    public function setFlag($flag, $value = null)
    {
        if ($flag!=='mcrypt'&&$flag!=='openssl'){
            throw new Exception ("$flag not supported");
        }
        if ($value===false){
            $this->$flag = false;
        } else if ($value!==true&&$value!==null){
            throw new Exception ("$value must be boolean or null (default)");
        } else if (
            $flag === 'mcrypt' && function_exists('mcrypt_create_iv') ||
            $flag === 'openssl' && function_exists('openssl_random_pseudo_bytes')
        ){
            $this->$flag = true;
        } else if ($value === null){
            $this->$flag = false;
        } else { //if ($flag === true)
            throw new Exception ("$flag not supported");
        }
    }

    /**
     * @return boolean
     */
    public function getMcrypt()
    {
        return $this->mcrypt;
    }

    /**
     * @return boolean
     */
    public function getOpenssl()
    {
        return $this->openssl;
    }

    /**
     * @param boolean $urandom
     * @throws Exception
     */
    public function setUrandom($urandom = null)
    {
        if ($urandom===false){
            $this->urandom = false;
        } else if ($urandom!==true&&$urandom!==null){
            throw new Exception ('$urandom must be boolean or null (default)');
        } else if (is_readable('/dev/urandom')){
            if ($this->urandomFileHandler = fopen('/dev/urandom', 'r')!==false){
                $this->urandom = true;
            } else {
                throw new Exception('/dev/urandom is readable but can\'t get a file handler with fopen.');
            }
        } else if ($urandom === null){
            $this->urandom = false;
        } else { //if ($urandom === true)
            throw new Exception ('$urandom not supported');
        }
    }

    /**
     * @return boolean
     */
    public function getUrandom()
    {
        return $this->urandom;
    }
    
    /**
     * generates crypto safe bytes and puts them into a string of chars
     * 
     * @param $byteCount number of crypto safe random chars to generate
     * @return string string of generated crypto safe random chars
     */
    public function getRandomBytesString($byteCount){
        $chars = '';
        // try mcrypt
        if ($this->mcrypt) {
            $chars = mcrypt_create_iv($byteCount, MCRYPT_DEV_URANDOM);
        }
        // if it fails, use openssl_random_pseudo_bytes
        if (!$chars && $this->openssl) {
            $chars = openssl_random_pseudo_bytes($byteCount);
        }
        // if it fails, try /dev/urandom (will work only on unix based systems)
        if (!$chars && $this->urandom) {
            while (($len  = strlen($chars))< $byteCount) {
                $chars .= fread($this->urandomFileHandler, $byteCount - $len);
            }
        }
        // if it fails, throw an Exception
        if ($len = strlen($chars) < $byteCount) {
            throw new Exception('Cannot use a cryptographically secure PRNG.');
        }
        return $chars;
    }
    /**
     * generates crypto safe ints inside a given range
     * 
     * Works like mt_rand. (2 parameters required. If no parameter is given default range is [0,PHP_INT_MAX])
     * 
     * @param int $min min int from the range to be generated. Defaults to 0
     * @param int $max nax int from the range to be generated. Defaults to PHP_INT_MAX
     * @return int generated int
     * @throws Exception An exception with error message on invalid parameters
     */
    public function rand($min = 0, $max = null){
        if ($max === null) { $max = $this->defaultMax; }
        if (!is_int($min)||!is_int($max)) { throw new Exception('$min and $max must be integers'); }
        if ($min>$max) { throw new Exception('$min must be <= $max'); }
        // pow(2,$numBits-1) calculated as (pow(2,$numBits-2)-1) + pow(2,$numBits-2) to avoid overflow when $numBits is the number of bits of PHP_INT_MAX
        $maxSafe = (int) floor(
            ((pow(2,8*$this->intByteCount-2)-1) + pow(2,8*$this->intByteCount-2)) 
            / 
            ($max - $min)
        ) * ($max - $min);
        // discards anything above the last interval N * {0 .. max - min -1} that fits in {0 ..  2^(intBitCount-1)-1}
        do {
            $chars = $this->getRandomBytesString($this->intByteCount);
            $n = 0;
            for ($i=0;$i<$this->intByteCount;$i++) {$n|=(ord($chars[$i])<<(8*($this->intByteCount-$i-1)));}
        } while (abs($n)>$maxSafe);
        return (abs($n)%($max-$min+1))+$min;
    }

    /**
     * Constructor. It sets the size of an int in bytes and available random byte generation methods
     *
     * @param mixed $defaultMax (optional, null for default) the default max integer to be generated. Defaults to null which sets the default max to mt_getrandmax()
     * @param mixed $intByteCount (optional, null for default) the int size in bytes (must be an integer > 0). Defaults to null which sets the estimated integer size in bytes for the system (using PHP_INT_MAX)
     * @param mixed $mcrypt (optional, boolean, null for default) set mcrypt availability
     * @param mixed $openssl (optional, boolean, null for default) set openssl availability
     * @param mixed $urandom (optional, boolean, null for default) set urandom availability
     * @throws Exception an exception containing an error message on invalid parameters or other errors
     */
    public function __construct($intByteCount = null, $defaultMax = null, $mcrypt = null, $openssl = null, $urandom = null){
        if ($intByteCount === null){
            $this->setIntByteCount(
                (strlen(PHP_INT_MAX) === 10)?4:
                    ((strlen(PHP_INT_MAX) === 19)?8:
                        ((strlen(PHP_INT_MAX) === 39)?16:
                            ((strlen(PHP_INT_MAX) === 77)?32:
                                2))));
        } else {
            $this->setIntByteCount($intByteCount);
        }
        if ($defaultMax === null){
            $this->setDefaultMax(mt_getrandmax());
        } else {
            $this->setDefaultMax($defaultMax);
        }
        $this->setFlag('mcrypt',$mcrypt);
        $this->setFlag('openssl',$openssl);
        $this->setUrandom($urandom);
    }
    /**
     * Destructor function. It just closes the /dev/urandom file handler, if opened.
     */
    public function __destruct(){
        if (is_resource($this->urandomFileHandler) && (get_resource_type($this->urandomFileHandler)==='file')){
            fclose ($this->urandomFileHandler);
        }
    }
} 
