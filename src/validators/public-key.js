'use strict'

const setImmediate = require('async/setImmediate')
const multihashing = require('multihashing-async')

const errcode = require('err-code')

/**
 * Validator for publick key records.
 * Verifies that the passed in record value is the PublicKey
 * that matches the passed in key.
 *
 * @param {Buffer} key - A valid key is of the form `'/pk/<keymultihash>'`
 * @param {Buffer} publicKey - The public key to validate against (protobuf encoded).
 * @param {function(Error)} callback
 * @returns {undefined}
 */
const validatePublicKeyRecord = (key, publicKey, callback) => {
  const done = (err) => setImmediate(() => callback(err))

  if (!Buffer.isBuffer(key)) {
    const errMsg = `"key" must be a Buffer`

    return done(errcode(new Error(errMsg), 'ERR_INVALID_KEY'))
  }

  if (key.length < 3) {
    const errMsg = 'invalid public key record'

    return done(errcode(new Error(errMsg), 'ERR_INVALID_PUBLIC_KEY'))
  }

  const prefix = key.slice(0, 4).toString()

  if (prefix !== '/pk/') {
    const errMsg = 'key was not prefixed with /pk/'

    return done(errcode(new Error(errMsg), 'ERR_INVALID_KEY_PREFIX'))
  }

  const keyhash = key.slice(4)

  multihashing(publicKey, 'sha2-256', (err, publicKeyHash) => {
    if (err) {
      return done(err)
    }

    if (!keyhash.equals(publicKeyHash)) {
      const errMsg = 'public key does not match passed in key'

      return done(errcode(new Error(errMsg), 'ERR_PUBLIC_KEY_NOT_MATCHING_KEY'))
    }

    done()
  })
}

module.exports = {
  func: validatePublicKeyRecord,
  sign: false
}
