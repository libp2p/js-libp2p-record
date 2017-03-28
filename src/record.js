'use strict'

const protobuf = require('protocol-buffers')
const Buffer = require('safe-buffer').Buffer
const assert = require('assert')
const PeerId = require('peer-id')

const pb = protobuf(require('./record.proto')).Record
const utils = require('./utils')

class Record {
  /**
   * @param {Buffer} [key]
   * @param {Buffer} [value]
   * @param {PeerId} [author]
   * @param {Date} [recvtime]
   */
  constructor (key, value, author, recvtime) {
    if (key) {
      assert(Buffer.isBuffer(key), 'key must be a Buffer')
    }

    if (value) {
      assert(Buffer.isBuffer(value), 'value must be a buffer')
    }

    this.key = key
    this.value = value
    this.author = author
    this.timeReceived = recvtime
    this.signature = null
  }

  /**
   * Returns the blob protected by the record signature.
   *
   * @returns {Buffer}
   */
  blobForSignature () {
    return Buffer.concat([
      Buffer.from(this.key),
      this.value,
      this.author.id
    ])
  }

  /**
   * @returns {Buffer}
   */
  encode () {
    return pb.encode(this.prepareEncode())
  }

  /**
   * Return the object format ready to be given to the protobuf library.
   *
   * @returns {Object}
   */
  prepareEncode () {
    return {
      key: this.key,
      value: this.value,
      author: this.author.id,
      signature: this.signature,
      timeReceived: this.timeReceived && utils.toRFC3339(this.timeReceived)
    }
  }
  /**
   * @param {PrivateKey} privKey
   * @param {function(Error, Buffer)} callback
   * @returns {undefined}
   */
  encodeSigned (privKey, callback) {
    const blob = this.blobForSignature()

    privKey.sign(blob, (err, signature) => {
      if (err) {
        return callback(err)
      }

      this.signature = signature

      let rec
      try {
        rec = this.encode()
      } catch (err) {
        return callback(err)
      }

      callback(null, rec)
    })
  }

  /**
   * Decode a protobuf encoded record.
   *
   * @param {Buffer} raw
   * @returns {Record}
   */
  static decode (raw) {
    const dec = pb.decode(raw)
    return Record.fromDecoded(dec)
  }

  /**
   * Create a record from the raw object returnde from the
   * protobuf library.
   *
   * @param {Object} obj
   * @returns {Record}
   */
  static fromDecoded (obj) {
    let recvtime
    if (obj.timeReceived) {
      recvtime = utils.parseRFC3339(obj.timeReceived)
    }

    const rec = new Record(
      obj.key, obj.value, new PeerId(obj.author), recvtime
    )

    rec.signature = obj.signature

    return rec
  }
  /**
   * Verify the signature of a record against the given public key.
   *
   * @param {PublicKey} pubKey
   * @param {function(Error)} callback
   * @returns {undefined}
   */
  verifySignature (pubKey, callback) {
    const blob = this.blobForSignature()

    pubKey.verify(blob, this.signature, (err, good) => {
      if (err) {
        return callback(err)
      }

      if (!good) {
        return callback(new Error('Invalid record signature'))
      }

      callback()
    })
  }
}

module.exports = Record
