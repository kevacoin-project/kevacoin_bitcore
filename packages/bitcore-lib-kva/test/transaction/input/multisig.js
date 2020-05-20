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
var MultiSigInput = bitcore.Transaction.Input.MultiSig;

describe('MultiSigInput', function() {

  var privateKey1 = new PrivateKey('MaQ8svxCwpEq9m6y8BpFxuMz2wz6BZKuj9zLTQbioqsofawCb9nB');
  var privateKey2 = new PrivateKey('MeACrr2Gp1G1iY25AKbZGRSmKxYrGQBgpa7Y4ZU2RKFXTqLSFu4Q');
  var privateKey3 = new PrivateKey('MbUWwdhvnSeHzqMvPbkGrSfmdW6BPXSq6z3fZh935Dyn3zz11Fyt');
  var public1 = privateKey1.publicKey;
  var public2 = privateKey2.publicKey;
  var public3 = privateKey3.publicKey;
  var address = new Address('VVoJLTjUqT7Ge12yaynjcHez8jC2H7Cf8A');

  var output = {
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script("5221032611ca4956673edbfdb60b852bfd4a7e5bc74bab0bacfc44b687fbbb961212522103d66a84ec9b17c4f30fe3f2be4393661151691d0fea062bf05a2422505ee3e8e32103264afc80e3c4a019689502e4e19d45393085f5fb5b1c0b438cbdb82f671ecb2f53ae"),
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
  it('can count missing signatures, signed with key 3 and 1', function() {
    var transaction = new Transaction()
        .from(output, [public1, public2, public3], 2, {noSorting: true})
        .to(address, 1000000);
    var input = transaction.inputs[0];

    input.countSignatures().should.equal(0);

    transaction.sign(privateKey3);
    input.countSignatures().should.equal(1);
    input.countMissingSignatures().should.equal(1);
    input.isFullySigned().should.equal(false);

    transaction.sign(privateKey1);
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
    input._estimateSize().should.equal(147);
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
    var roundtrip = new MultiSigInput(input.toObject(), null, null, null, {noSorting: true});
    roundtrip.toObject().should.deep.equal(input.toObject());
  });
  it('roundtrips to/from object when not signed', function() {
    var transaction = new Transaction()
      .from(output, [public1, public2, public3], 2, {noSorting: true})
      .to(address, 1000000);
    var input = transaction.inputs[0];
    var roundtrip = new MultiSigInput(input.toObject(), null, null, null, {noSorting: true});
    roundtrip.toObject().should.deep.equal(input.toObject());
  });
  it('can parse list of signature buffers, from TX signed with key 1 and 2', function() {
    var transaction = new Transaction("020000000140c1ae9d6933e4a08594f814ba73a4e94d19c8a83f45784b1684b3a3f84ee666000000009300483045022100ee871bc02ac889981c6a0e9d801ca9691090b91e7aa37e87950bf0d1b1c44b6b02201bb4fbcb54a07aacb4d751bbcac61cbecf1d1513f513005b6a9ca75b31f2b77801483045022100e4f4dd66f1acf27c9565da922caa77684499d56c74264dd1bd306d63b71074e60220621e534cf287003fb2915aad40115caf0a14b5f7ed015414f2f46fcd92a4fee201ffffffff0140420f000000000017a914d1f1666783441c985ba89b19557d1ecfc862264c8700000000");

    var inputObj = transaction.inputs[0].toObject();
    inputObj.output = output;
    transaction.inputs[0] = new Transaction.Input(inputObj);

    inputObj.signatures = MultiSigInput.normalizeSignatures(
        transaction,
        transaction.inputs[0],
        0,
        transaction.inputs[0].script.chunks.slice(1).map(function(s) { return s.buf; }),
        [public1, public2, public3]
    );

    transaction.inputs[0] = new MultiSigInput(inputObj, [public1, public2, public3], 2, null, {noSorting: true});

    transaction.inputs[0].signatures[0].publicKey.should.deep.equal(public1);
    transaction.inputs[0].signatures[1].publicKey.should.deep.equal(public2);
    should.equal(transaction.inputs[0].signatures[2], undefined);
    transaction.inputs[0].isValidSignature(transaction, transaction.inputs[0].signatures[0]).should.be.true;
    transaction.inputs[0].isValidSignature(transaction, transaction.inputs[0].signatures[1]).should.be.true;
  });
  it('can parse list of signature buffers, from TX signed with key 3 and 1', function() {
    var transaction = new Transaction("020000000140c1ae9d6933e4a08594f814ba73a4e94d19c8a83f45784b1684b3a3f84ee666000000009300483045022100ee871bc02ac889981c6a0e9d801ca9691090b91e7aa37e87950bf0d1b1c44b6b02201bb4fbcb54a07aacb4d751bbcac61cbecf1d1513f513005b6a9ca75b31f2b77801483045022100ad638312be661edfe2f25e802f40caed915c3bd33831de4f9856ebd82ae8349d02200c70da9d3d84dfd77e444aac8fd6704414bab73a8d693aa4992eeaac4913392001ffffffff0140420f000000000017a914d1f1666783441c985ba89b19557d1ecfc862264c8700000000");

    var inputObj = transaction.inputs[0].toObject();
    inputObj.output = output;
    transaction.inputs[0] = new Transaction.Input(inputObj);

    inputObj.signatures = MultiSigInput.normalizeSignatures(
        transaction,
        transaction.inputs[0],
        0,
        transaction.inputs[0].script.chunks.slice(1).map(function(s) { return s.buf; }),
        [public1, public2, public3]
    );

    transaction.inputs[0] = new MultiSigInput(inputObj, [public1, public2, public3], 2, null, {noSorting: true});

    transaction.inputs[0].signatures[0].publicKey.should.deep.equal(public1);
    should.equal(transaction.inputs[0].signatures[1], undefined);
    transaction.inputs[0].signatures[2].publicKey.should.deep.equal(public3);
    transaction.inputs[0].isValidSignature(transaction, transaction.inputs[0].signatures[0]).should.be.true;
    transaction.inputs[0].isValidSignature(transaction, transaction.inputs[0].signatures[2]).should.be.true;
  });
});
