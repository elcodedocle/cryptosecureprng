cryptosecureprng
================

mt_rand crypto safe byte strings and ints from a given range

Ever wanted a crypto safe mt_rand()? Not useful for many things I guess (maybe not useful at all), 
but I recently wanted to build a class able to pick random words from a dictionary in a safe way, 
so they could be used as passwords. I probably overdid it... The result is my attempt on a 
"cryptographically secure" mt_rand implementation, including a wrapper for selecting and using the 
best random bytes generator from available extensions and /dev/urandom (about 100 times slower than 
mt_rand on a single core, by the way, so it's clearly open for improvement if you want to fork it ;-))

Have fun.-
