# node-oclc-wskey

[![build status](https://secure.travis-ci.org/malantonio/node-oclc-wskey.png)](https://travis-ci.org/malantonio/node-oclc-wskey)

Module to construct a [WebService Key][wskey] for use with OCLC services.

```
npm install oclc-wskey
```

## usage

### `var key = new WSKey(key, secret /*, user */)`

Where `user` is an object with the keys `principalID` and `principalIDNS`.
Depending on what you're planning, you may not need to provide a one.

You can also pass an object as the sole parameter. Use these keys:

key            | value
---------------|----------------
`key`          | the public key
`secret`       | the secret key
`user`         | an object with `principalID` and `principalIDNS` keys
`redirect_uri` | redirect uri associated with the key
`scope`        | an array of scopes associated with the key

`redirect_uri` and `scope` have no bearing on this module's only function
(`key.HMACSignature`), but are necessary for [generating Access Tokens][access-token].

### `var sig = key.HMACSignature(method, uri /*, user */)`

Returns an HMAC signature for `method` and `uri`. Uses the instantiated user by
default, but can be overridden with a different user.

## example

```javascript
var WSKey = require('oclc-wskey')
var https = require('https')
var url = require('url')
var me = { principalID: 'principalID', principalIDNS: 'principalIDNS' }
var key = new WSKey('wskey', 'secret', me)
var addr = url.parse('https://circ.sd00.worldcat.org/LHR?q=oclc:656296916')

var opts = {
  hostname: addr.hostname,
  path: addr.path,
  headers: {
    'Authorization': key.HMACSignature('GET', url.format(addr)),
    'Accept': 'application/json'
  }
}

https.get(opts, function (res) {
  res.pipe(process.stdout)
})
```

## license
MIT

[wskey]: http://www.oclc.org/developer/develop/authentication/what-is-a-wskey.en.html
[access-token]: https://github.com/malantonio/node-oclc-access-token
