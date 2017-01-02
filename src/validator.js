'use strict'

const Record = require('./record')

/**
 * Checks a record and ensures it is still valid.
 * It runs the needed validators.
 *
 * @param {Object} validators
 * @param {Buffer} record - The record in protobuf format
 * @param {function(Error)} callback
 * @returns {undefined}
 */
const verifyRecord = (validators, record, callback) => {
  const dec = Record.decode(record)
  const key = dec.key
  const parts = key.split('/')

  if (parts.length < 3) {
    // No validator available
    return callback()
  }

  const validator = validators[parts[1]]

  if (!validator) {
    return callback(new Error('Invalid record keytype'))
  }

  validator.func(key, dec.value, callback)
}

/**
 * Check if a given record was signed.
 *
 * @param {Object} validators
 * @param {Buffer} record
 * @returns {boolean}
 */
const isSigned = (validators, record) => {
  const dec = Record.decode(record)
  const key = dec.key
  const parts = key.split('/')

  if (parts.length < 3) {
    // No validator available
    return false
  }

  const validator = validators[parts[1]]

  if (!validator) {
    throw new Error('Invalid record keytype')
  }

  return validator.sign
}

module.exports = {
  verifyRecord: verifyRecord,
  isSigned: isSigned,
  validators: require('./validators')
}
