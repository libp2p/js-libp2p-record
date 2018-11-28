'use strict'

const ipns = require('ipns')
const setImmediate = require('async/setImmediate')

const validateIpnsRecord = (key, record, callback) => {
  const done = (err) => setImmediate(() => callback(err))

  if (!Buffer.isBuffer(key)) {
    return done(new Error('"key" must be a Buffer'))
  }

  if (key.length < 3) {
    return done(new Error('invalid public key record'))
  }

  const prefix = key.slice(0, 6).toString()

  if (prefix !== '/ipns/') {
    return done(new Error('key was not prefixed with /ipns/'))
  }

  console.log('record', record)

  ipns.validator.validate(record, key, done)
}

module.exports = {
  func: validateIpnsRecord,
  sign: false
}
