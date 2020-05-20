'use strict';
/* jshint unused: false */

var should = require('chai').should();
var expect = require('chai').expect;
var _ = require('lodash');

var bitcore = require('../../..');
var Transaction = bitcore.Transaction;
var PrivateKey = bitcore.PrivateKey;
var Address = bitcore.Address;
var Script = bitcore.Script;
var Signature = bitcore.crypto.Signature;
var MultiSigScriptHashInput = bitcore.Transaction.Input.MultiSigScriptHash;

describe('MultiSigScriptHashInput', function() {

  var privateKey1 = new PrivateKey('MaQ8svxCwpEq9m6y8BpFxuMz2wz6BZKuj9zLTQbioqsofawCb9nB');
  var privateKey2 = new PrivateKey('MeACrr2Gp1G1iY25AKbZGRSmKxYrGQBgpa7Y4ZU2RKFXTqLSFu4Q');
  var privateKey3 = new PrivateKey('MbUWwdhvnSeHzqMvPbkGrSfmdW6BPXSq6z3fZh935Dyn3zz11Fyt');
  var public1 = privateKey1.publicKey;
  var public2 = privateKey2.publicKey;
  var public3 = privateKey3.publicKey;
  var address = new Address('VVoJLTjUqT7Ge12yaynjcHez8jC2H7Cf8A');
  var witnessAddress = new Address([public1, public2, public3], 2, null, Address.PayToWitnessScriptHash);

  var output = {
    address: 'VVoJLTjUqT7Ge12yaynjcHez8jC2H7Cf8A',
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(address),
    satoshis: 1000000
  };

  var witnessOutput = {
    address: 'kva1qhq2n9n5f9wm39f4kv5eu6hzu3l5k9qv0ffftc0u32xj04s9jr48seag86d',
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(witnessAddress),
    satoshis: 1000000
  };

  it('can count missing signatures', function() {
    var transaction = new Transaction()
      .from(output, [public1, public2, public3], 2, {noSorting: true})
      .to(address, 1000000);
    var input = transaction.inputs[0];

    input.countSignatures().should.equal(0);

    transaction.sign(privateKey1);
    input.countSignatures().should.equal(1);
    input.countMissingSignatures().should.equal(1);
    input.isFullySigned().should.equal(false);

    transaction.sign(privateKey2);
    input.countSignatures().should.equal(2);
    input.countMissingSignatures().should.equal(0);
    input.isFullySigned().should.equal(true);
  });
  it('returns a list of public keys with missing signatures', function() {
    var transaction = new Transaction()
      .from(output, [public1, public2, public3], 2, {noSorting: true})
      .to(address, 1000000);
    var input = transaction.inputs[0];

    _.every(input.publicKeysWithoutSignature(), function(publicKeyMissing) {
      var serialized = publicKeyMissing.toString();
      return serialized === public1.toString() ||
              serialized === public2.toString() ||
              serialized === public3.toString();
    }).should.equal(true);
    transaction.sign(privateKey1);
    _.every(input.publicKeysWithoutSignature(), function(publicKeyMissing) {
      var serialized = publicKeyMissing.toString();
      return serialized === public2.toString() ||
              serialized === public3.toString();
    }).should.equal(true);
  });
  it('can clear all signatures', function() {
    var transaction = new Transaction()
      .from(output, [public1, public2, public3], 2, {noSorting: true})
      .to(address, 1000000)
      .sign(privateKey1)
      .sign(privateKey2);

    var input = transaction.inputs[0];
    input.isFullySigned().should.equal(true);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });
  it('can estimate how heavy is the output going to be', function() {
    var transaction = new Transaction()
      .from(output, [public1, public2, public3], 2, {noSorting: true})
      .to(address, 1000000);
    var input = transaction.inputs[0];
    input._estimateSize().should.equal(98.25);
  });
  it('uses SIGHASH_ALL by default', function() {
    var transaction = new Transaction()
      .from(output, [public1, public2, public3], 2, {noSorting: true})
      .to(address, 1000000);
    var input = transaction.inputs[0];
    var sigs = input.getSignatures(transaction, privateKey1, 0);
    sigs[0].sigtype.should.equal(Signature.SIGHASH_ALL);
  });
  it('roundtrips to/from object', function() {
    var transaction = new Transaction()
      .from(output, [public1, public2, public3], 2, {noSorting: true})
      .to(address, 1000000)
      .sign(privateKey1);
    var input = transaction.inputs[0];
    var roundtrip = new MultiSigScriptHashInput(input.toObject(), null, null, null, {noSorting: true});
    roundtrip.toObject().should.deep.equal(input.toObject());
  });
  it('roundtrips to/from object when not signed', function() {
    var transaction = new Transaction()
      .from(output, [public1, public2, public3], 2, {noSorting: true})
      .to(address, 1000000);
    var input = transaction.inputs[0];
    var roundtrip = new MultiSigScriptHashInput(input.toObject(), null, null, null, {noSorting: true});
    roundtrip.toObject().should.deep.equal(input.toObject());
  });
  it('will get the scriptCode for nested witness', function() {
    var address = Address.createMultisig([public1, public2, public3], 2, 'testnet', true);
    var utxo = {
      address: address.toString(),
      txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
      outputIndex: 0,
      script: new Script(address),
      satoshis: 1000000
    };
    var transaction = new Transaction()
      .from(utxo, [public1, public2, public3], 2, true)
      .to(address, 1000000);
    var input = transaction.inputs[0];
    var scriptCode = input.getScriptCode();
    scriptCode.toString('hex').should.equal('695221032611ca4956673edbfdb60b852bfd4a7e5bc74bab0bacfc44b687fbbb961212522103264afc80e3c4a019689502e4e19d45393085f5fb5b1c0b438cbdb82f671ecb2f2103d66a84ec9b17c4f30fe3f2be4393661151691d0fea062bf05a2422505ee3e8e353ae');
  });
  it('will get the satoshis buffer for nested witness', function() {
    var address = Address.createMultisig([public1, public2, public3], 2, 'testnet', true);
    var utxo = {
      address: address.toString(),
      txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
      outputIndex: 0,
      script: new Script(address),
      satoshis: 1000000
    };
    var transaction = new Transaction()
      .from(utxo, [public1, public2, public3], 2, true)
      .to(address, 1000000);
    var input = transaction.inputs[0];
    var satoshisBuffer = input.getSatoshisBuffer();
    satoshisBuffer.toString('hex').should.equal('40420f0000000000');
  });

  describe('P2WSH', function() {
    it('can count missing signatures', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2)
        .to(address, 1000000);
      var input = transaction.inputs[0];

      input.countSignatures().should.equal(0);

      transaction.sign(privateKey1);
      input.countSignatures().should.equal(1);
      input.countMissingSignatures().should.equal(1);
      input.isFullySigned().should.equal(false);

      transaction.sign(privateKey2);
      input.countSignatures().should.equal(2);
      input.countMissingSignatures().should.equal(0);
      input.isFullySigned().should.equal(true);
    });
    it('returns a list of public keys with missing signatures', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2)
        .to(address, 1000000);
      var input = transaction.inputs[0];

      _.every(input.publicKeysWithoutSignature(), function(publicKeyMissing) {
        var serialized = publicKeyMissing.toString();
        return serialized === public1.toString() ||
                serialized === public2.toString() ||
                serialized === public3.toString();
      }).should.equal(true);
      transaction.sign(privateKey1);
      _.every(input.publicKeysWithoutSignature(), function(publicKeyMissing) {
        var serialized = publicKeyMissing.toString();
        return serialized === public2.toString() ||
                serialized === public3.toString();
      }).should.equal(true);
    });
    it('can clear all signatures', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2)
        .to(address, 1000000)
        .sign(privateKey1)
        .sign(privateKey2);

      var input = transaction.inputs[0];
      input.isFullySigned().should.equal(true);
      input.clearSignatures();
      input.isFullySigned().should.equal(false);
    });
    it('can estimate how heavy is the output going to be', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      input._estimateSize().should.equal(64.25);
    });
    it('uses SIGHASH_ALL by default', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var sigs = input.getSignatures(transaction, privateKey1, 0);
      sigs[0].sigtype.should.equal(Signature.SIGHASH_ALL);
    });
    it('roundtrips to/from object', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2)
        .to(address, 1000000)
        .sign(privateKey1);
      var input = transaction.inputs[0];
      var roundtrip = new MultiSigScriptHashInput(input.toObject());
      roundtrip.toObject().should.deep.equal(input.toObject());
    });
    it('roundtrips to/from object when not signed', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var roundtrip = new MultiSigScriptHashInput(input.toObject());
      roundtrip.toObject().should.deep.equal(input.toObject());
    });
    it('will get the scriptCode', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2, true)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var scriptCode = input.getScriptCode();
      scriptCode.toString('hex').should.equal('695221032611ca4956673edbfdb60b852bfd4a7e5bc74bab0bacfc44b687fbbb961212522103264afc80e3c4a019689502e4e19d45393085f5fb5b1c0b438cbdb82f671ecb2f2103d66a84ec9b17c4f30fe3f2be4393661151691d0fea062bf05a2422505ee3e8e353ae');
    });
    it('will get the satoshis buffer', function() {
      var transaction = new Transaction()
        .from(witnessOutput, [public1, public2, public3], 2, true)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var satoshisBuffer = input.getSatoshisBuffer();
      satoshisBuffer.toString('hex').should.equal('40420f0000000000');
    });
  });

});
