var test = require('tape')
var WSKey = require('./')
var keyopts = {
  key: 'abc123',
  secret: 'SECRETSHH',
}
var user = {principalID: 'principalID', principalIDNS: 'principalIDNS'}
var wsk = new WSKey(keyopts)
var url = 'https://www.oclc.org/test/?cee=dee and bee&aye=bee'

test('WSKey constructed from object', function (t) {
  var w = new WSKey(keyopts)

  t.deepEqual(w.scope, [], 'w.scope is created as an empty array')
  t.deepEqual(w.user, {}, 'w.user is called as an empty object')
  t.end()
})

test('WSKey stores scope / redirect_uri if used', function (t) {
  var o = {
    key: keyopts.key,
    secret: keyopts.secret,
    redirect_uri: 'http://localhost',
    scope: ['WMS_CIRC', 'WMS_NCIP']
  }
  var k = new WSKey(o)

  t.equal(k.scope, o.scope)
  t.equal(k.redirect_uri, o.redirect_uri)
  t.end()
})

test('WSKey.scope is constructed from string if provided', function (t) {
  var o = {
    key: 'key',
    secret: 'secret',
    scope: 'WMS_NCIP'
  }
  var expect = [o.scope]
  var k = WSKey(o)

  t.deepEqual(k.scope, expect, '`scope` strings are converted to arrays')
  t.end()
})

test('WSKey constructed from parameters', function (t) {
  var key = 'key'
  var secret = 'secret'
  var w = new WSKey(key, secret, user)

  t.equal(w.key, 'key', 'key passed to w.key')
  t.equal(w.secret, 'secret', 'secret passed to w.secret')
  t.deepEqual(w.user, user)
  t.end()
})

test('HMAC signature works ', function (t) {
    var sig = 'Yy9/wwejQt0Pk6yHS7ziRO+c+APCvtO29Egg/1NfY6Q='
    var debug = {time: 123456, nonce: 99999}
    var header = wsk.HMACSignature('get', url, null, debug)

    t.ok(header.indexOf('signature="' + sig + '"') > -1, 'signature matches that in header')
    t.end()
});

test('for-real hmac looks okay', function (t) {
  var header = wsk.HMACSignature('GET', url, user)
  var reg = new RegExp([
    'http\\:\\/\\/www\\.worldcat\\.org\\/wskey\\/v2\\/hmac\\/v1',
    'clientId="' + wsk.key + '",',
    'timestamp="(\\d+)",',
    'nonce="([A-Za-z0-9]+)",',
    'signature="([A-Za-z0-9\\=\\\\\\+\\/]+)",',
    'principalID="' + user.principalID + '",',
    'principalIDNS="' + user.principalIDNS + '"',
  ].join(' '))

  t.ok(reg.test(header), 'regexp looks okay')
  t.notOk(/clientId="(undefined|null)"/.test(header), '`clientId` is defined/not null')
  t.notOk(/timestamp="(undefined|null)"/.test(header), '`timestamp` is defined/not null')
  t.notOk(/nonce="(undefined|null")/.test(header), '`nonce` is defined/not null')
  t.notOk(/signature="(undefined|null)"/.test(header), '`signature` is defined/not null')
  t.notOk(/principalID="(undefined|null)"/.test(header), '`principalID` is defined/not null')
  t.notOk(/principalIDNS="(undefined|null)"/.test(header), '`principalIDNS` is defined/not null')
  t.end()
})

test('user gets passed to signature', function(t) {
  var w = new WSKey('abc123', 'SECRETSHH', user)
  var h = w.HMACSignature('GET', url)

  t.ok(h.indexOf('principalID="principalID"') > -1, 'principalID is in signature')
  t.ok(h.indexOf('principalIDNS="principalIDNS"') > -1, 'principalIDNS is in signature')
  t.end()
});

test('new user gets passed to HMAC sig', function (t) {
    var newUser = {principalID: 'zyx', principalIDNS: 'wvu'}
    var header = wsk.HMACSignature('GET', url, newUser)

    t.ok(header.indexOf('principalID="zyx"') > -1, 'principalID is in header')
    t.ok(header.indexOf('principalIDNS="wvu"') > -1, 'principalIDNS is in header')
    t.end()
})

test('public exists + key alias works', function (t) {
  var key1 = new WSKey({public: 'abc123', secret: 'shhh'})
  var key2 = new WSKey({key: 'abc123', secret: 'shhh'})
  var newKey = 'new public key'

  t.deepEqual(key1, key2)

  key1.public = newKey

  t.equal(key1.public, newKey)
  t.equal(key1.key, newKey)

  key2.key = newKey

  t.equal(key2.public, newKey)
  t.equal(key2.key, newKey)

  t.end()
})

test('attempting HMAC signature without public and/or secret key throws', function (t) {
  var keys = [new WSKey('abc123'), new WSKey, new WSKey]

  keys[1].secret = 'shhh'

  t.plan(keys.length)

  keys.forEach(function (key) {
    t.throws(function () {
      key.HMACSignature('GET', url)
    })
  })
})
