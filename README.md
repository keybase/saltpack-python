Lots of stuff.


All Your Base
=============

A generalized BaseN scheme that is *compatible with Base64*.

For an alphabet of N characters, the number of bytes in a block and the
number of characters in the encoding of that block have to obey:

    256 ^ bytes_size <= N ^ chars_size

Take the `log_2` of both sides:

    8 * bytes_size <= log_2(N) * chars_size

Requiring both sizes to be integers, we get our two rules:

    bytes_size = floor( chars_size * log_2(N) / 8 )
    chars_size =  ceil( bytes_size * 8 / log_2(N) )

Now for the compatibility step. Our encoding space is going to have
"whole extra bits" equal to:

    extra = floor( chars_size * log_2(N) - bytes_size * 8 )

That means that when we convert bytes to an integer (en route to
reencoding that integer in our base), we have room to bitshift left by
those `extra` places. In power-of-two bases like 64, that ends up being
equivalent to the rule "when encoding a partial block, use the most
significant bits first," which is how Base64 is defined.
