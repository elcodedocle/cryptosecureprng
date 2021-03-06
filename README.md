cryptosecureprng
================

#####*mt_rand for the moderately paranoid citizen*

 Copyright (C) 2014 Gael Abadin<br/>
 License: [MIT Expat][1] / beerware<br/>
 [![Code Climate](https://codeclimate.com/github/elcodedocle/cryptosecureprng.png)](https://codeclimate.com/github/elcodedocle/cryptosecureprng)
 
### Motivation

Ever wanted a [crypto safe](http://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) mt_rand()? Not useful for many things I guess (maybe not useful at all), 
but I recently wanted to build a [class able to pick random words from a dictionary in a safe way](https://github.com/elcodedocle/chbspassgen), 
so they could be used as passwords ([Correct, horse. That's a battery staple][2]). I probably overdid it... The result is my attempt on a 
"cryptographically secure" PRNG implementation with an mt_rand alike interface, including a wrapper for selecting and using the 
best random bytes generator from available extensions and /dev/urandom (about 100 times slower than 
mt_rand on a single core, by the way, so clearly there is plenty of room for improvement if you want to fork it ;-))

### How to use

In a similar way as mt_rand(), random integers are chosen from a given range following a uniform distribution:

```php
require_once 'CryptoSecurePRNG.php';
$secGen =  new synapp\info\tools\passwordgenerator\cryptosecureprng\CryptoSecurePRNG();
$randInt = $secGen->rand(); //between 0 and mt_getrandmax()
$randInt = $secGen->rand(1,100); //between 1 and 100
$randInt = $secGen->rand(-50,50); //between -50 and 50
```

You can also get a string of random bytes:

```php
require_once 'CryptoSecurePRNG.php';
$secGen =  new synapp\info\tools\passwordgenerator\cryptosecureprng\CryptoSecurePRNG();
$stringLength = 20; // number of random chars to be generated
$stringOfRandomChars = $secGen->getRandomBytesString($stringLength); // generate a string of $stringLength random ascii chars (non printable too)

```

And here is the code to visualize the output using matlab:

```php
// PHP code, uses cryptosecureprng rand() to generate the samples
require_once 'CryptoSecurePRNG.php';
$prng = new synapp\info\tools\passwordgenerator\cryptosecureprng\CryptoSecurePRNG();
$out=''; 
for ($i=0;$i<1280;$i++) for ($j=0;$j<720;$j++) { 
  $out .= $prng->rand(0,255).','.$prng->rand(0,255).','.$prng->rand(0,255).',';   
}
$fh = fopen('testout.txt','w');
fwrite ($fh, $out);
fclose($fh);
```

```matlab
% Matlab code, reads and displays the generated samples
x=csvread('testout.txt');
C = reshape (x,720,1280,3);
C = uint8(C);
imwrite(C,'rgb_output.bmp');
hist(x,256);
saveas(gcf,'hist_output','png');
```

The rgb output looks like this ([Uncompressed source](http://i4.minus.com/iZno4ib9xJYp1.bmp)):

![1280x720 0-255 rgb output](http://i.minus.com/jZno4ib9xJYp1.bmp "shrinked 1280x720 0-255 rgb output. Github uses jpeg compression. Uncompressed source available at http://i4.minus.com/iZno4ib9xJYp1.bmp")

And here is the 256-interval histogram:

![256-interval, 1280x720x3 0-255 samples histogram](http://i.minus.com/jnAXCdcY51T8o.png "256-interval 1280x720x3 samples histogram")

Check the code (or generate the docs using phpdocumentor) if you want more info on tweaks and available parameters.

If you like this class, feel free to buy me a beer ;-)

bitcoin: 15i9QKZqLuNdcyseHpjpZiPcty6FMazxk2 

dogecoin: DCjimHzRu25smyjnEb7V9qFuVyf6P2JjBf 

paypal: http://goo.gl/iQd1UL


Have fun.-

[1]: https://raw.githubusercontent.com/elcodedocle/cryptosecureprng/master/LICENSE
[2]: http://xkcd.com/936/
