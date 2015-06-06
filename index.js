module.exports = WSKey;

function WSKey (key, secret, options) {
    if ( !(this instanceof WSKey) ) return new WSKey(key, secret, options);

    this.key = key;
    this.secret = secret;
    this.opt = options || {};

    this.addUser(this.opt.user);
    
    this.time = this.nonce = null;
}

WSKey.prototype.addUser = function(user) {
    this.user = (user && user.principalID && user.principalIDNS) ? user : {};
}

WSKey.prototype.hasUser = function() {
    return this.user && this.user.principalID && this.user.principalIDNS;
}

WSKey.prototype.HMACSignature = function (method, url, options) {
    var options = options || this.opt || {}
      , user = options.user
      , norm = this._normalizeRequest(method, url, options)
      , sig
      ;

    sig = 'http://www.worldcat.org/wskey/v2/hmac/v1'
        + ' clientId="' + this.key + '",'
        + ' timestamp="' + this.time + '",'
        + ' nonce="' + this.nonce + '",'
        + ' signature="' + createHMACDigest(norm, this.secret) + '"'
        ;

    if ( user ) {
      sig += ', principalID="' + user.principalID + '"'
          +  ', principalIDNS="' + user.principalIDNS + '"'
          ;
    }

    this.time = this.nonce = null;

    return sig;
}

WSKey.prototype._normalizeRequest = function (method, reqUrl, options) {
    var url = require('url')
      , parsedSigUrl = url.parse('https://www.oclc.org/wskey')
      , parsedReqUrl = url.parse(reqUrl)
      , qs = parsedReqUrl.query

      , sigPort = parsedSigUrl.protocol === 'https:' ? 443 : 80
      
      , options = options || this.opt || {}
      , time = options._debug ? options._debug.time : (new Date()).getTime().toString().substr(0, 10)
      , nonce = options._debug ? options._debug.nonce : createNonce()
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

function createHMACDigest(normalized, secret) {
    var crypto = require('crypto')
      , hmac = crypto.createHmac('sha256', secret)
      ;

    hmac.update(normalized);
    return hmac.digest('base64');
};

function createNonce () {
    return Math.ceil(
            (new Date()).getMilliseconds() 
            * Math.random() 
            * 1000000
           );
}