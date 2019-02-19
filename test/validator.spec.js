/* eslint max-nested-callbacks: ["error", 8] */
/* eslint-env mocha */
'use strict'

const chai = require('chai')
chai.use(require('dirty-chai'))
const expect = chai.expect
const crypto = require('libp2p-crypto')
const PeerId = require('peer-id')

const libp2pRecord = require('../src')
const validator = libp2pRecord.validator
const Record = libp2pRecord.Record

const fixture = require('./fixtures/go-key-records.js')

const generateCases = (hash) => {
  return {
    valid: {
      publicKey: [
        Buffer.concat([
          Buffer.from('/pk/'),
          hash
        ])
      ]
    },
    invalid: {
      publicKey: [
        // missing hashkey
        Buffer.from('/pk/'),
        // not the hash of a key
        Buffer.concat([
          Buffer.from('/pk/'),
          Buffer.from('random')
        ]),
        // missing prefix
        hash
      ]
    }
  }
}

describe('validator', () => {
  let key
  let hash
  let cases

  before(async () => {
    key = await crypto.keys.generateKeyPair('rsa', 1024)
    hash = await key.public.hash()
    cases = generateCases(hash)
  })

  describe('verifyRecord', () => {
    it('calls matching validator', () => {
      const k = Buffer.from('/hello/you')
      const rec = new Record(k, Buffer.from('world'), new PeerId(hash))

      const validators = {
        hello: {
          func (key, value) {
            expect(key).to.eql(k)
            expect(value).to.eql(Buffer.from('world'))
          },
          sign: false
        }
      }
      return validator.verifyRecord(validators, rec)
    })

    it('calls not matching any validator', () => {
      const k = Buffer.from('/hallo/you')
      const rec = new Record(k, Buffer.from('world'), new PeerId(hash))

      const validators = {
        hello: {
          func (key, value) {
            expect(key).to.eql(k)
            expect(value).to.eql(Buffer.from('world'))
          },
          sign: false
        }
      }
      return expect(
        () => validator.verifyRecord(validators, rec)
      ).to.throw(
        /Invalid record keytype/
      )
    })
  })

  describe('validators', () => {
    it('exports pk', () => {
      expect(validator.validators).to.have.keys(['pk'])
    })

    describe('public key', () => {
      it('exports func and sign', () => {
        const pk = validator.validators.pk

        expect(pk).to.have.property('func')
        expect(pk).to.have.property('sign', false)
      })

      it('does not error on valid record', () => {
        return Promise.all(cases.valid.publicKey, (k) => {
          return validator.validators.pk.func(k, key.public.bytes)
        })
      })

      it('throws on invalid records', () => {
        return Promise.all(cases.invalid.publicKey, (k) => {
          return expect(
            () => validator.validators.pk.func(k, key.public.bytes)
          ).to.throw()
        })
      })
    })
  })

  describe('go interop', () => {
    it('record with key from from go', async () => {
      const pubKey = crypto.keys.unmarshalPublicKey(fixture.publicKey)

      const hash = await pubKey.hash()
      const k = Buffer.concat([Buffer.from('/pk/'), hash])
      return validator.validators.pk.func(k, pubKey.bytes)
    })
  })
})
