# node-oclc-wskey

Module to construct a [WebService Key](http://www.oclc.org/developer/develop/authentication/what-is-a-wskey.en.html) 
for use with OCLC services.

## var key = new WSKey(key, secret, options)

Returns a WSKey instance object. `options` can be an object with the keys:

### `user`

An object with `principalID` and `principalIDNS` keys. 

### `_debug`

An object with `time` (posix timestamp), `nonce`, and `bodyHash` keys. Since OCLC does not currently use a `bodyHash`, 
this can be left out.


## key.HMACSignature(requestMethod, url, options)

Generates the [HMAC Signature](http://www.oclc.org/developer/develop/authentication/hmac-signature.en.html) header needed
for authorization with most OCLC services. 

## Example

```
var WSKey = require('oclc-wskey')
  , request = require('request')
  , me = { principalID: 'principalID', principalIDNS: 'principalIDNS' }
  , key = new WSKey('wskey', 'secret', { user: me })
  , url = 'https://circ.sd00.worldcat.org/LHR?q=oclc:656296916'
  , headers = {
        'Authorization': key.HMACSignature('GET', url),
        'Accept': 'application/json'
    }
  ;

request.get(url, { 'headers': headers }, function(err, response, body) {
    console.log(body);
})
```

## License
MIT
