'use strict'

/**
 * Select the best record out of the given records.
 *
 * @param {Object} selectors
 * @param {string} k
 * @param {Array<Buffer>} records
 * @returns {number} - The index of the best record.
 */
const bestRecord = (selectors, k, records) => {
  if (records.length === 0) {
    throw new Error('No records given')
  }

  const parts = k.split('/')

  if (parts.length < 3) {
    throw new Error('Record key does not have a selector function')
  }

  const selector = selectors[parts[1]]

  if (!selector) {
    throw new Error(`Unrecognized key prefix: ${parts[1]}`)
  }

  return selector(k, records)
}

module.exports = {
  bestRecord: bestRecord,
  selectors: require('./selectors')
}
