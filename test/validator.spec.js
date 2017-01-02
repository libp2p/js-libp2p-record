/* eslint max-nested-callbacks: ["error", 8] */
/* eslint-env mocha */
'use strict'

var expect = require('chai').expect
const waterfall = require('async/waterfall')
const each = require('async/each')
const parallel = require('async/parallel')
const crypto = require('libp2p-crypto')
const mh = require('multihashes')
const PeerId = require('peer-id')

const libp2pRecord = require('../src')
const validator = libp2pRecord.validator
const Record = libp2pRecord.Record

const fixture = require('./fixtures/go-key-records.js')

const makeRecord = (key, k, callback) => {
  PeerId.createFromPrivKey(key.bytes, (err, id) => {
    if (err) {
      return callback(err)
    }
    let rec
    try {
      rec = new Record(k, crypto.randomBytes(10), id)
    } catch (err) {
      return callback(err)
    }
    callback(null, rec)
  })
}

const generateCases = (hash) => {
  return {
    valid: {
      publicKey: [
        `/pk/${mh.toB58String(hash)}`
      ]
    },
    invalid: {
      publicKey: [
        // missing hashkey
        '/pk/',
        // not the hash of a key
        `/pk/${mh.toB58String(new Buffer('random'))}`,
        // missing prefix
        mh.toB58String(hash)
      ]
    }
  }
}

describe('validator', () => {
  let key
  let hash
  let cases

  before((done) => {
    waterfall([
      (cb) => crypto.generateKeyPair('rsa', 1024, cb),
      (pair, cb) => {
        key = pair
        pair.public.hash(cb)
      },
      (_hash, cb) => {
        hash = _hash
        cases = generateCases(hash)
        cb()
      }
    ], done)
  })

  describe('verifyRecord', () => {
    it('calls matching validator', (done) => {
      const k = '/hello/you'
      const rec = new Record(k, new Buffer('world'), new PeerId(hash))

      const validators = {
        hello: {
          func (key, value, cb) {
            expect(key).to.be.eql(k)
            expect(value).to.be.eql(new Buffer('world'))
            cb()
          },
          sign: false
        }
      }
      validator.verifyRecord(validators, rec.encode(), done)
    })
  })

  describe('isSigned', () => {
    it('returns false for missing validator', (done) => {
      makeRecord(key, '/hello', (err, rec) => {
        expect(err).to.not.exist
        const validators = {}

        expect(
          validator.isSigned(validators, rec.encode())
        ).to.be.eql(
          false
        )
        done()
      })
    })

    it('throws on unkown validator', (done) => {
      makeRecord(key, '/hello/world', (err, rec) => {
        expect(err).to.not.exist
        const validators = {}

        expect(
          () => validator.isSigned(validators, rec.encode())
        ).to.throw(
          /Invalid record keytype/
        )

        done()
      })
    })

    it('returns the value from the matching validator', (done) => {
      const validators = {
        hello: {sign: true},
        world: {sign: false}
      }

      parallel([
        (cb) => makeRecord(key, '/hello/world', cb),
        (cb) => makeRecord(key, '/world/hello', cb)
      ], (err, recs) => {
        expect(err).to.not.exist

        expect(
          validator.isSigned(validators, recs[0].encode())
        ).to.be.eql(
          true
        )

        expect(
          validator.isSigned(validators, recs[1].encode())
        ).to.be.eql(
          false
        )

        done()
      })
    })
  })

  describe('validators', () => {
    it('exports pk', () => {
      expect(validator.validators).to.have.keys(['pk'])
    })

    describe('public key', () => {
      it('exports func and sing', () => {
        const pk = validator.validators.pk

        expect(pk).to.have.property('func')
        expect(pk).to.have.property('sign', false)
      })

      it('does not error on valid record', (done) => {
        each(cases.valid.publicKey, (k, cb) => {
          validator.validators.pk.func(k, key.public.bytes, cb)
        }, done)
      })

      it('throws on invalid records', (done) => {
        each(cases.invalid.publicKey, (k, cb) => {
          validator.validators.pk.func(k, key.public.bytes, (err) => {
            expect(err).to.exist
            cb()
          })
        }, done)
      })
    })
  })

  describe('go interop', () => {
    it('record with key from from go', (done) => {
      const pubKey = crypto.unmarshalPublicKey(fixture.publicKey)

      pubKey.hash((err, hash) => {
        expect(err).to.not.exist
        const k = `/pk/${mh.toB58String(hash)}`

        validator.validators.pk.func(k, pubKey.bytes, done)
      })
    })
  })
})
