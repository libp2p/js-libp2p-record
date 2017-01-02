/* eslint-env mocha */
'use strict'

const expect = require('chai').expect
const crypto = require('libp2p-crypto')
const waterfall = require('async/waterfall')
const parallel = require('async/parallel')
const PeerId = require('peer-id')

const libp2pRecord = require('../src')
const Record = libp2pRecord.Record

const fixture = require('./fixtures/go-record.js')

const date = new Date(Date.UTC(2012, 1, 25, 10, 10, 10, 10))

describe('record', () => {
  let key
  let otherKey
  let id

  before((done) => {
    waterfall([
      (cb) => parallel([
        (cb) => crypto.generateKeyPair('rsa', 1024, cb),
        (cb) => crypto.generateKeyPair('rsa', 1024, cb)
      ], cb),
      (keys, cb) => {
        otherKey = keys[0]
        key = keys[1]

        PeerId.createFromPrivKey(key.bytes, cb)
      },
      (_id, cb) => {
        id = _id

        cb()
      }
    ], done)
  })

  it('new', () => {
    const rec = new Record(
      'hello',
      new Buffer('world'),
      id
    )

    expect(rec).to.have.property('key', 'hello')
    expect(rec).to.have.property('value').eql(new Buffer('world'))
    expect(rec).to.have.property('author').eql(id)
  })

  it('encode & decode', () => {
    const rec = new Record('hello', new Buffer('world'), id, date)
    const dec = Record.decode(rec.encode())

    expect(dec).to.have.property('key', 'hello')
    expect(dec).to.have.property('value').eql(new Buffer('world'))
    expect(dec).to.have.property('author')
    expect(dec.author.id.equals(id.id)).to.be.eql(true)
    expect(dec.timeReceived).to.be.eql(date)
  })

  it('encodeSigned', (done) => {
    const rec = new Record('hello2', new Buffer('world2'), id, date)
    rec.encodeSigned(key, (err, enc) => {
      expect(err).to.not.exist

      const dec = Record.decode(enc)
      expect(dec).to.have.property('key', 'hello2')
      expect(dec).to.have.property('value').eql(new Buffer('world2'))
      expect(dec).to.have.property('author')
      expect(dec.author.id.equals(id.id)).to.be.eql(true)
      expect(dec.timeReceived).to.be.eql(date)

      const blob = rec.blobForSignature()

      key.sign(blob, (err, signature) => {
        expect(err).to.not.exist

        expect(dec.signature).to.be.eql(signature)
        done()
      })
    })
  })

  describe('verifySignature', () => {
    it('valid', (done) => {
      const rec = new Record('hello', new Buffer('world'), id)

      rec.encodeSigned(key, (err, enc) => {
        expect(err).to.not.exist

        rec.verifySignature(key.public, done)
      })
    })

    it('invalid', (done) => {
      const rec = new Record('hello', new Buffer('world'), id)
      rec.encodeSigned(key, (err, enc) => {
        expect(err).to.not.exist

        rec.verifySignature(otherKey.public, (err) => {
          expect(err).to.match(/Invalid record signature/)
          done()
        })
      })
    })
  })

  describe('go interop', () => {
    it('no signature', () => {
      const dec = Record.decode(fixture.encoded)
      expect(dec).to.have.property('key', 'hello')
      expect(dec).to.have.property('value').eql(new Buffer('world'))
      expect(dec).to.have.property('author')
    })

    it('with signature', () => {
      const dec = Record.decode(fixture.encodedSigned)
      expect(dec).to.have.property('key', 'hello')
      expect(dec).to.have.property('value').eql(new Buffer('world'))
      expect(dec).to.have.property('author')
      expect(dec).to.have.property('signature')
    })
  })
})
