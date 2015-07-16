var test = require('tape')
  , WSKey = require('./')
  , wsk = new WSKey('abc123', 'SECRETSHH')
  , user = { principalID: 'principalID', principalIDNS: 'principalIDNS' }
  , url = 'https://www.oclc.org/test/?cee=dee and bee&aye=bee'
  ;

test('normalized request is normalized', function(t) {
    var conf = 'abc123\n123456\n99999\n\nGET\nwww.oclc.org\n443\n/wskey\naye=bee\ncee=dee%20and%20bee\n'
      , debug = { time: 123456, nonce: 99999 }
      , norm = wsk._normalizeRequest('get', url, debug)
      ;

    t.equal(norm, conf);
    t.end();
});

test('hmac\'d sig is hmac\'d', function(t) {
    var sig = 'Yy9/wwejQt0Pk6yHS7ziRO+c+APCvtO29Egg/1NfY6Q='
      , debug = { time: 123456, nonce: 99999 }
      , header = wsk.HMACSignature('get', url, debug)
      ;

    t.ok(header.indexOf('signature="' + sig + '"') > -1, 'signature matches that in header');
    t.end();
});

test('new user gets passed', function(t) {
    var newUser = { principalID: 'zyx', principalIDNS: 'wvu' }
    var header = wsk.HMACSignature('GET', url, newUser);

    t.ok(header.indexOf('principalID="zyx"') > -1, 'new user\'s principalID is in header');
    t.ok(header.indexOf('principalIDNS="wvu"') > -1, 'new user\'s principalIDNS is in header');
    t.end();
});

test('user gets passed when initialized', function(t) {
  var w = new WSKey('abc123', 'SECRETSHH', user);
  var h = w.HMACSignature('GET', url);

  t.ok(w.hasUser(), 'user exists');

  t.ok(h.indexOf('principalID="principalID"') > -1, 'principalID is in header');
  t.ok(h.indexOf('principalIDNS="principalIDNS"') > -1, 'principalIDNS is in header');

  t.end();
});

test('addUser works', function(t) {
  t.notOk(wsk.hasUser(), 'WSKey initially has no user')

  wsk.addUser(user);
  t.deepEquals(user, wsk.user, 'addUser assigns user');

  wsk.addUser();
  t.deepEquals({}, wsk.user, 'passing no user zeros-out WSKey.user');
  t.end();
});

if ( process.env.WSKEY && process.env.WSKEY_SECRET && process.env.INST && process.env.SCOPE ) {
  test('requestAccessToken', function(t) {
    var wk = new WSKey(process.env.WSKEY, process.env.WSKEY_SECRET)
      , authInstID = process.env.INST
      , scope = process.env.SCOPE.split(',')
      ;

    wk.requestAccessToken(authInstID, scope, function(err, resp, auth) {
      t.ok(err === null, 'no error returned')
      t.ok(auth.match(/^Bearer/), 'Bearer header passed to callback')
      t.end()
    });
  });
}