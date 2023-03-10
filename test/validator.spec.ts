/* eslint max-nested-callbacks: ["error", 8] */
/* eslint-env mocha */

import { expect } from 'aegir/chai'
import { generateKeyPair, unmarshalPublicKey } from '@libp2p/crypto/keys'
import { fromString as uint8ArrayFromString } from 'uint8arrays/from-string'
import * as validator from '../src/validators.js'
import { Libp2pRecord } from '../src/index.js'
import * as fixture from './fixtures/go-key-records.js'
import type { Validators } from '@libp2p/interface-dht'

interface Cases {
  valid: {
    publicKey: Uint8Array[]
  }
  invalid: {
    publicKey: Array<{
      data: Uint8Array
      code: string
    }>
  }
}

const generateCases = (hash: Uint8Array): Cases => {
  return {
    valid: {
      publicKey: [
        Uint8Array.of(
          ...uint8ArrayFromString('/pk/'),
          ...hash
        )
      ]
    },
    invalid: {
      publicKey: [{
        data: uint8ArrayFromString('/pk/'),
        code: 'ERR_INVALID_RECORD_KEY_TOO_SHORT'
      }, {
        data: Uint8Array.of(...uint8ArrayFromString('/pk/'), ...uint8ArrayFromString('random')),
        code: 'ERR_INVALID_RECORD_HASH_MISMATCH'
      }, {
        data: hash,
        code: 'ERR_INVALID_RECORD_KEY_BAD_PREFIX'
      }, {
        // @ts-expect-error invalid input
        data: 'not a buffer',
        code: 'ERR_INVALID_RECORD_KEY_NOT_BUFFER'
      }]
    }
  }
}

describe('validator', () => {
  let key: any
  let hash: Uint8Array
  let cases: Cases

  before(async () => {
    key = await generateKeyPair('RSA', 1024)
    hash = await key.public.hash()
    cases = generateCases(hash)
  })

  describe('verifyRecord', () => {
    it('calls matching validator', async () => {
      const k = uint8ArrayFromString('/hello/you')
      const rec = new Libp2pRecord(k, uint8ArrayFromString('world'), new Date())

      const validators: Validators = {
        async hello (key, value) {
          expect(key).to.eql(k)
          expect(value).to.eql(uint8ArrayFromString('world'))
        }
      }
      await validator.verifyRecord(validators, rec)
    })

    it('calls not matching any validator', async () => {
      const k = uint8ArrayFromString('/hallo/you')
      const rec = new Libp2pRecord(k, uint8ArrayFromString('world'), new Date())

      const validators: Validators = {
        async hello (key, value) {
          expect(key).to.eql(k)
          expect(value).to.eql(uint8ArrayFromString('world'))
        }
      }
      await expect(validator.verifyRecord(validators, rec))
        .to.eventually.rejectedWith(
          /Invalid record keytype/
        )
    })
  })

  describe('validators', () => {
    it('exports pk', () => {
      expect(validator.validators).to.have.keys(['pk'])
    })

    describe('public key', () => {
      it('exports func', () => {
        const pk = validator.validators.pk

        expect(pk).to.be.a('function')
      })

      it('does not error on valid record', async () => {
        return await Promise.all(cases.valid.publicKey.map(async (k) => {
          await validator.validators.pk(k, key.public.bytes)
        }))
      })

      it('throws on invalid records', async () => {
        return await Promise.all(cases.invalid.publicKey.map(async ({ data, code }) => {
          try {
            //
            await validator.validators.pk(data, key.public.bytes)
          } catch (err: any) {
            expect(err.code).to.eql(code)
            return
          }
          expect.fail('did not throw an error with code ' + code)
        }))
      })
    })
  })

  describe('go interop', () => {
    it('record with key from from go', async () => {
      const pubKey = unmarshalPublicKey(fixture.publicKey)

      const hash = await pubKey.hash()
      const k = Uint8Array.of(...uint8ArrayFromString('/pk/'), ...hash)
      await validator.validators.pk(k, pubKey.bytes)
    })
  })
})
