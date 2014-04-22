cryptosecureprng
================

#####*mt_rand crypto safe byte strings and ints from a given range*

 Copyright (C) 2014 Gael Abadin<br/>
 License: [MIT Expat][1] / beerware
 
### Motivation

Ever wanted a crypto safe mt_rand()? Not useful for many things I guess (maybe not useful at all), 
but I recently wanted to build a class able to pick random words from a dictionary in a safe way, 
so they could be used as passwords ([Correct, horse. That's a battery staple][2]). I probably overdid it... The result is my attempt on a 
"cryptographically secure" mt_rand implementation, including a wrapper for selecting and using the 
best random bytes generator from available extensions and /dev/urandom (about 100 times slower than 
mt_rand on a single core, by the way, so it's clearly open for improvement if you want to fork it ;-))

### How to use

In a similar way as mt_rand(), random integers are chosen from a given range following a uniform distribution:

```php
require_once 'CryptoSecurePRNG.php';
$secGen =  new synapp\info\tools\CryptoSecurePRNG();
$randInt = $secGen->rand(); //between 0 and mt_getrandmax()
$randInt = $secGen->rand(1,100); //between 1 and 100
$randInt = $secGen->rand(-50,50); //between -50 and 50
```

You can also get a string of random bytes:

```php
require_once 'CryptoSecurePRNG.php';
$secGen =  new synapp\info\tools\CryptoSecurePRNG();
$stringLength = 20; // number of random chars to be generated
$stringOfRandomChars = $secGen->getRandomBytesString($stringLength); // generate a string of $stringLength random ascii chars (non printable too)

```

Check the code (or generate the docs using phpdocumentor) if you want more info on tweaks and available parameters.

If you like this class, feel free to buy me a beer ;-)

bitcoin: 15i9QKZqLuNdcyseHpjpZiPcty6FMazxk2 

dogecoin: DCjimHzRu25smyjnEb7V9qFuVyf6P2JjBf 

paypal: http://goo.gl/iQd1UL


Have fun.-

[1]: https://raw.githubusercontent.com/elcodedocle/cryptosecureprng/master/LICENSE
[2]: http://xkcd.com/936/
