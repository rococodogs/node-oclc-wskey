module.exports = WSKey;

function WSKey (key, secret, user) {
    if ( !(this instanceof WSKey) ) return new WSKey(key, secret, user);

    this.key = key;
    this.secret = secret;
    
    this.addUser(user)
    
    this.time = this.nonce = null;
}

WSKey.prototype.addUser = function(user) {
    this.user = isUser(user) ? user : {};
}

WSKey.prototype.hasUser = function() {
    return isUser(this.user);
}

WSKey.prototype.removeUser = function() {
    this.user = {}
}

WSKey.prototype.requestAccessToken = function(authInstID, contextInstID, user, scope, cb) {
  var request = require('request');
  var opts = {};

  // variation 1: authInstID is contextInstID
  // requestAccessToken(authInstId, user, scope, cb)
  if (typeof scope === 'function') {
    return this.requestAccessToken(authInstId, authInstId, contextInstID, user, scope);
  }

  // variation 2: authInstID is contextInstID + no user specified
  // requestAccessToken(authInstId, scope, cb)
  else if ( typeof user === 'function' ) {
    return this.requestAccessToken(authInstID, authInstID, this.user, contextInstID, user)
  }

  // variation 3: opts object + callback
  // requestAccessToken({ ... }, cb );
  else if ( typeof authInstID === 'object' ) {
    opts = authInstID;
    cb = typeof contextInstID === 'function' ? contextInstID : noop;
    authInstID = opts.authenticatingInstitutionID || opts.contextInstitutionID;
    contextInstID = opts.contextInstitutionID || authInstID;
    scope = opts.scope || [];
    user = opts.user || this.user || {};
  } 

  if ( typeof scope === 'string' ) scope = [scope]

  var url, tokenResponse;

  url = 'https://authn.sd00.worldcat.org/oauth2/accessToken?grant_type=client_credentials'
      + '&authenticatingInstitutionId=' + authInstID
      + '&contextInstitutionId=' + contextInstID
      + '&scope=' + scope.join(' ')
      ;

  request.post(
    url, 
    { 
      headers: { 
        'Authorization': this.HMACSignature('POST', url),
        'Accept': 'application/json' 
      }
    },
    function(err, resp, body) {
      if (err) return cb(err, null);

      body = JSON.parse(body);

      if (body.code) return cb(Error(body.message), null);
      
      return cb(err, body, 'Bearer: ' + body.access_token);
    })
}

WSKey.prototype.HMACSignature = function (method, url, user, _debug) {
    // lousy check for debug vs. user
    if ( !_debug ) {
      if ( isUser(user) ) {
        _debug = {};
      } else {
        _debug = user;
        user = null;
      }
    }

    if ( !user && this.hasUser() ) user = this.user;

    var norm = this._normalizeRequest(method, url, _debug || {})
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

WSKey.prototype._normalizeRequest = function (method, reqUrl, _debug) {
    var url = require('url')
      , parsedSigUrl = url.parse('https://www.oclc.org/wskey')
      , parsedReqUrl = url.parse(reqUrl)
      , qs = parsedReqUrl.query

      , sigPort = parsedSigUrl.protocol === 'https:' ? 443 : 80
      
      , _debug = _debug || {}
      , time = _debug.time || (new Date()).getTime().toString().substr(0, 10)
      , nonce = _debug.nonce || createNonce()
      , bodyHash = _debug.bodyHash || ''

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

function createNonce() {
    return Math.ceil(
            (new Date()).getMilliseconds() 
            * Math.random() 
            * 1000000
           );
}

function isUser(user) {
  if ( user === undefined ) return false;
  if ( typeof user !== 'object' ) return false;
  if ( !user.principalID || !user.principalIDNS ) return false;
  return true;
}

function noop() {}
