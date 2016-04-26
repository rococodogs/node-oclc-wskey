module.exports = WSKey;

function WSKey (pub, secret, user) {
  if ( !(this instanceof WSKey) ) return new WSKey(pub, secret, user);
  var opts = {}

  if (typeof pub === 'object') {
    opts = pub
    this.public = opts.public || opts.key
    this.secret = opts.secret
    this.redirect_uri = opts.redirect_uri
    this.user = opts.user || {}

    if (Array.isArray(opts.scope))
      this.scope = opts.scope
    else if (typeof opts.scope === 'string' && opts.scope !== '')
      this.scope = opts.scope.split(' ')
    else
      this.scope = []

  } else {
    this.public = pub
    this.secret = secret
    this.user = user || {}
    this.scope = []
  }

  // add `key.key` alias
  Object.defineProperty(this, 'key', {
    get: function () { return this.public },
    set: function (val) { this.public = val }
  })
}

WSKey.prototype.HMACSignature = function (method, url, user, opts) {
  if (!opts) opts = {}

  var time = opts.time || (new Date()).getTime().toString().substr(0, 10)
  var nonce = opts.nonce || createNonce()

  if (!user) user = this.user

  var normopts = {
    time: time,
    nonce: nonce,
    bodyHash: opts.bodyHash || '',
    method: method,
    url: url,
    key: this.public
  }

  var norm = normalizeRequest(normopts)
  var sig = 'http://www.worldcat.org/wskey/v2/hmac/v1'
          + ' clientId="' + this.public + '",'
          + ' timestamp="' + time + '",'
          + ' nonce="' + nonce + '",'
          + ' signature="' + createHMACDigest(norm, this.secret) + '"'

  if (user.principalID && user.principalIDNS) {
    sig += ', principalID="' + user.principalID + '"'
        +  ', principalIDNS="' + user.principalIDNS + '"'
  }

  return sig;
}

function normalizeRequest (opts) {
  var url = require('url')
  var parsedSigUrl = url.parse('https://www.oclc.org/wskey')
  var parsedReqUrl = url.parse(opts.url)
  var qs = parsedReqUrl.query
  var sigPort = parsedSigUrl.protocol === 'https:' ? 443 : 80
  var time = opts.time
  var nonce = opts.nonce
  var bodyHash = opts.bodyHash
  var query

  if (qs)
    query = qs.split('&').sort().join('\n')

  var normalized = [
    opts.key,
    time,
    nonce,
    bodyHash,
    opts.method.toUpperCase(),
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
