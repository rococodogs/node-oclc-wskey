module.exports = WSKey;

function WSKey (key, secret, options) {
    if ( !(this instanceof WSKey) ) return new WSKey(key, secret, options);

    this.key = key;
    this.secret = secret;
    this.opt = options;

    this.time = this.nonce = null;
}

WSKey.prototype.HMACSignature = function (method, url, options) {
    var options = options || this.opt || {}
      , norm = this._normalizeRequest(method, url, options)
      , sig
      ;

    sig = 'http://www.worldcat.org/wskey/v2/hmac/v1'
        + ' clientId="' + this.key + '",'
        + ' timestamp="' + this.time + '",'
        + ' nonce="' + this.nonce + '",'
        + ' signature="' + this._createHMACDigest(norm) + '"'
        ;

    if ( options.user ) {
      sig += ', principalID="' + options.user.principalID + '"'
          +  ', principalIDNS="' + options.user.principalIDNS + '"'
          ;
    }

    this.time = this.nonce = null;

    return sig;
}

WSKey.prototype._createHMACDigest = function (normalized) {
    var crypto = require('crypto')
      , hmac = crypto.createHmac('sha256', this.secret)
      ;

    hmac.update(normalized);
    return hmac.digest('base64');
};

WSKey.prototype._createNonce = function () {
    return Math.ceil(
            (new Date()).getMilliseconds() 
            * Math.random() 
            * 1000000
           );
}

WSKey.prototype._normalizeRequest = function (method, reqUrl, options) {
    var url = require('url')
      , parsedSigUrl = url.parse('https://www.oclc.org/wskey')
      , parsedReqUrl = url.parse(reqUrl)
      , qs = parsedReqUrl.query

      , sigPort = parsedSigUrl.protocol === 'https:' ? 443 : 80
      
      , options = options || this.opt || {}
      , time = options._debug ? options._debug.time : (new Date()).getTime().toString().substr(0, 10)
      , nonce = options._debug ? options._debug.nonce : this._createNonce()
      , bodyHash = options._debug ? options._debug.bodyHash : (options.bodyHash || '')

      , query, normalized
      ;

    this.time = time;
    this.nonce = nonce;

    if ( qs ) {
      query = qs.split('&').sort().join('\n');
      query = query.replace(/[^\s%\=]/g, function(match) { return encodeURIComponent(match); });
    }

    normalized = [
        this.key,
        this.time,
        this.nonce,
        bodyHash,
        method.toUpperCase(),
        parsedSigUrl.host,
        sigPort,
        parsedSigUrl.path
    ];

    if ( query ) normalized.push(query);

    return normalized.join('\n') + '\n';
}
