# 3.2.1

`key.HMACSignature` throws if `key` is missing `public` or `secret` values

# 3.2.0

Adds `public` attribute to replace `key`. Adds `key` alias to reference
`public` for backwards compat.

# 3.1.0

Removes complexity of setting `user` property. Won't bail if `principalID`
and/or `principalIDNS` properties aren't set.

# 3.0.2

Readme changes

# 3.0.1

Clean up `key.scope` setting on construction. Fix `nonce="undefined"` and
`timestamp="undefined"` issues + add tests.

# 3.0.0

Overhaul of everything. Removes `requestAccessToken`, `addUser`, `getUser`,
`removeUser`, and `_normalizeRequest` methods. Constructor allows opts object
in addition to `(key, secret, user)` signature.

# 2.1.0

`requestAccessToken` cleanup.

# 2.0.0

Adds `removeUser` and `requestAccessToken` methods. Overhauls `HMACSignature`
debugging. `_createHMACDigest` and `_createNonce` 'private' methods removed

# 1.1.1

Adds repository and bugs data to `package.json`

# 1.1.0

Adds `addUser` and `hasUser` methods. `addUser` will attach a user to the key
if `principalID` and `principalIDNS` fields exist.

# 1.0.1

When constructing HMAC Signature, check that a user's `principalID` and
`principalIDNS` are set first.
