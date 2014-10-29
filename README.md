angular-ecdsa
==============

angular-ecdsa provides elliptic curve cryptographic library for Angular.js to be used with bitcoin clients. it is just a wrapper of the [CryptoCoinJs](cryptocoinjs.com) libraries.

## work in progress
Pull requests are welcome

## Using the module

`bower install angular-ecdsa`

the module named 'ng-ecdsa' is available to you for your application

ex:

	angular.module('App',['ng-ecdsa'])
	  .factory('Product', 
	    ['ecdsa', 'crypto','Coinkey','buffer'], 
	      function(ecdsa, crypto, coinkey, buffer){
	        var Buffer = new buffer.Buffer();
	        ...
	      });

( Beware 'C' capital letter for Coinkey )

see [http://cryptocoinjs.com](cryptocoinjs.com) for ecdsa, crypto, and coinkey usage.



### Credits
[Henri Sack](https://github.com/sacketty/)


[![build status](https://secure.travis-ci.org/sacketty/eccrypto.png)](http://travis-ci.org/sacketty/eccrypto)

## Licence ##

The MIT License

Copyright (c) 2010 Matt Kane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.