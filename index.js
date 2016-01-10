module.exports = WSKey;

function WSKey (key, secret, user) {
  if ( !(this instanceof WSKey) ) return new WSKey(key, secret, user);
  var opts = {}

  Object.defineProperty(this, 'user', {
    get: function () { return this._user },
    set: function (u) {
      if (!u) u = {}
      if (!u.principalID || !u.principalIDNS) u = {}

      this._user = u
    }
  })

  if (typeof key === 'object') {
    opts = key
    this.key = opts.key
    this.secret = opts.secret
    this.redirect_uri = opts.redirect_uri
    this.scope = (opts.scope || '').split(' ')
    this.user = opts.user
  } else {
    this.key = key
    this.secret = secret
    this.user = user
  }
}

WSKey.prototype.HMACSignature = function (method, url, user, _debug) {
  if (!user) user = this.user

  var norm = normalizeRequest(this.key, method, url, _debug)
  var sig = 'http://www.worldcat.org/wskey/v2/hmac/v1'
          + ' clientId="' + this.key + '",'
          + ' timestamp="' + this.time + '",'
          + ' nonce="' + this.nonce + '",'
          + ' signature="' + createHMACDigest(norm, this.secret) + '"'

  if (user.principalID && user.principalIDNS) {
    sig += ', principalID="' + user.principalID + '"'
        +  ', principalIDNS="' + user.principalIDNS + '"'
  }

  return sig;
}

function normalizeRequest (key, method, reqUrl, debug) {
  var url = require('url')
  var parsedSigUrl = url.parse('https://www.oclc.org/wskey')
  var parsedReqUrl = url.parse(reqUrl)
  var qs = parsedReqUrl.query
  var sigPort = parsedSigUrl.protocol === 'https:' ? 443 : 80
  var _debug = debug || {}
  var time = _debug.time || (new Date()).getTime().toString().substr(0, 10)
  var nonce = _debug.nonce || createNonce()
  var bodyHash = _debug.bodyHash || ''
  var query

  if (qs)
    query = qs.split('&').sort().join('\n')

  var normalized = [
    key,
    time,
    nonce,
    bodyHash,
    method.toUpperCase(),
    parsedSigUrl.host,
    sigPort,
    parsedSigUrl.path
  ]

  if (query)
    normalized.push(query)

  return normalized.join('\n') + '\n'
}

function createHMACDigest(normalized, secret) {
  var crypto = require('crypto')
  var hmac = crypto.createHmac('sha256', secret)

  hmac.update(normalized);
  return hmac.digest('base64');
};

function createNonce() {
  return Math.ceil((new Date()).getMilliseconds() * Math.random() * 1000000)
}
