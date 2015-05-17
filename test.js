var test = require('tape')
  , WSKey = require('./')
  , wsk = new WSKey('abc123', 'SECRETSHH')
  , user = { principalID: 'principalID', principalIDNS: 'principalIDNS' }
  , url = 'https://www.oclc.org/test/?cee=dee and bee&aye=bee'
  ;

test('normalized request is normalized', function(t) {
    var conf = 'abc123\n123456\n99999\n\nGET\nwww.oclc.org\n443\n/wskey\naye=bee\ncee=dee%20and%20bee\n'
      , debug = { time: 123456, nonce: 99999 }
      , norm = wsk._normalizeRequest('get', url, {_debug: debug})
      ;

    t.equal(norm, conf);
    t.end();
});

test('hmac\'d sig is hmac\'d', function(t) {
    var sig = 'Yy9/wwejQt0Pk6yHS7ziRO+c+APCvtO29Egg/1NfY6Q='
      , debug = { time: 123456, nonce: 99999 }
      , header = wsk.HMACSignature('get', url, {_debug: debug} )
      ;

    t.ok(header.indexOf('signature="' + sig + '"') > -1, 'signature matches that in header');
    t.end();
});

test('user gets added when passed', function(t) {
    var header = wsk.HMACSignature('GET', url, {'user': user});

    t.ok(header.indexOf('principalID="principalID"') > -1, 'principalID exists in header');
    t.ok(header.indexOf('principalIDNS="principalIDNS"') > -1, 'principalIDNS exists in header');
    t.end();
});

test('user gets passed when initialized', function(t) {
  var w = new WSKey('abc123', 'SECRETSHH', {user: user});
  var h = w.HMACSignature('GET', url);

  t.ok(h.indexOf('principalID="principalID"') > -1);
  t.ok(h.indexOf('principalIDNS="principalIDNS"') > -1);

  t.end();
});

test('addUser works', function(t) {
  wsk.addUser(user);
  t.deepEquals(user, wsk.user, 'addUser assigns user');

  wsk.addUser();
  t.deepEquals({}, wsk.user, 'passing no user zeros-out WSKey.user');
  t.end();
});