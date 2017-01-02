'use strict'

const mh = require('multihashes')
const setImmediate = require('async/setImmediate')
const multihashing = require('multihashing-async')

/**
 * Validator for publick key records.
 * Verifies that the passed in record value is the PublicKey
 * that matches the passed in key.
 *
 * @param {string} key - A valid key is of the form `'/pk/<keymultihash>'`
 * @param {Buffer} publicKey - The public key to validate against (protobuf encoded).
 * @param {function(Error)} callback
 * @returns {undefined}
 */
const validatePublicKeyRecord = (key, publicKey, callback) => {
  const done = (err) => setImmediate(() => callback(err))

  if (!key || !typeof key === 'string') {
    return done(new Error('"key" must be a string'))
  }

  if (key.length < 3) {
    return done(new Error('invalid public key record'))
  }

  const prefix = key.slice(0, 4)

  if (prefix !== '/pk/') {
    return done(new Error('key was not prefixed with /pk/'))
  }

  const keyhash = mh.fromB58String(key.slice(4))

  multihashing(publicKey, 'sha2-256', (err, publicKeyHash) => {
    if (err) {
      return done(err)
    }

    if (!keyhash.equals(publicKeyHash)) {
      return done(new Error('public key does not match passed in key'))
    }

    done()
  })
}

module.exports = {
  func: validatePublicKeyRecord,
  sign: false
}
