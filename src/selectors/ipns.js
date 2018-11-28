'use strict'

const ipns = require('ipns')

/**
 * Best record selector, for public key records.
 * Simply returns the first record, as all valid public key
 * records are equal.
 *
 * @param {Buffer} k
 * @param {Array<Buffer>} records
 * @returns {number}
 */
const ipnsSelector = (k, records) => {
  // ipns.validator.validate(record, key, done)
  return 0
}

module.exports = ipnsSelector
