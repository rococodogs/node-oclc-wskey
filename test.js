var test = require('tape')
var WSKey = require('./')
var wsk = new WSKey('abc123', 'SECRETSHH')
var user = { principalID: 'principalID', principalIDNS: 'principalIDNS' }
var url = 'https://www.oclc.org/test/?cee=dee and bee&aye=bee'

test("hmac'd sig is hmac'd", function(t) {
    var sig = 'Yy9/wwejQt0Pk6yHS7ziRO+c+APCvtO29Egg/1NfY6Q='
    var debug = {time: 123456, nonce: 99999}
    var header = wsk.HMACSignature('get', url, null, debug)

    t.ok(header.indexOf('signature="' + sig + '"') > -1, 'signature matches that in header')
    t.end()
});

test('user gets passed to signature', function(t) {
  var w = new WSKey('abc123', 'SECRETSHH', user)
  var h = w.HMACSignature('GET', url)

  t.ok(h.indexOf('principalID="principalID"') > -1, 'principalID is in signature')
  t.ok(h.indexOf('principalIDNS="principalIDNS"') > -1, 'principalIDNS is in signature')
  t.end()
});

test('new user gets passed to HMAC sig', function(t) {
    var newUser = {principalID: 'zyx', principalIDNS: 'wvu'}
    var header = wsk.HMACSignature('GET', url, newUser)

    t.ok(header.indexOf('principalID="zyx"') > -1, "new user's principalID is in header")
    t.ok(header.indexOf('principalIDNS="wvu"') > -1, "new user\'s principalIDNS is in header")
    t.end()
})

test('scope works with array + string', function (t) {
  var scope_arr = ['WMS_NCIP', 'WMS_CIRCULATION']
  var scope_str = scope_arr.join(' ')
  var opt = {
    key: 'key',
    secret: 'secret',
    user: user,
    scope: scope_arr
  }

  var key_a = new WSKey(opt)

  t.deepEqual(key_a.scope, scope_arr, 'array is passed as is')

  opt['scope'] = scope_str

  var key_b = new WSKey(opt)

  t.deepEqual(key_b.scope, scope_arr, 'string is split into array')
  t.end()
})
