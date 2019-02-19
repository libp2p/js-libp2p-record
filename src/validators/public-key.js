'use strict'

const multihashing = require('multihashing-async')

/**
 * Validator for publick key records.
 * Verifies that the passed in record value is the PublicKey
 * that matches the passed in key.
 * If validation fails the returned Promise will reject with the error.
 *
 * @param {Buffer} key - A valid key is of the form `'/pk/<keymultihash>'`
 * @param {Buffer} publicKey - The public key to validate against (protobuf encoded).
 * @returns {Promise}
 */
const validatePublicKeyRecord = async (key, publicKey) => {
  if (!Buffer.isBuffer(key)) {
    throw new Error('"key" must be a Buffer')
  }

  if (key.length < 3) {
    throw new Error('invalid public key record')
  }

  const prefix = key.slice(0, 4).toString()

  if (prefix !== '/pk/') {
    throw new Error('key was not prefixed with /pk/')
  }

  const keyhash = key.slice(4)

  const publicKeyHash = await multihashing(publicKey, 'sha2-256')

  if (!keyhash.equals(publicKeyHash)) {
    throw new Error('public key does not match passed in key')
  }
}

module.exports = {
  func: validatePublicKeyRecord,
  sign: false
}
