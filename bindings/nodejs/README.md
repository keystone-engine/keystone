# node-keystone

`node-keystone` provides Node.js bindings for the
[Keystone](http://www.keystone-engine.org) assembler library, allowing
text data in to be assembled into `Buffer` objects using any of Keystone's
supported architectures.

### Install

`npm install /path/to/keystone/bindings/nodejs`

#### libkeystone

These bindings require you to have the Keystone library installed as it is
not included.

### Basic usage

```javascript
var keystone = require("keystone");
var assembly = "inc ecx; dec ebx"

var ks = new keystone.Ks(keystone.ARCH_X86, keystone.MODE_64);
console.log(ks.asm(assembly));
ks.close();
```

For other examples, see the `example.js` file.

### License

The source code is hereby released under the MIT License. The full text of the
license appears below.

Copyright (c) 2016 Ingmar Steen

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
