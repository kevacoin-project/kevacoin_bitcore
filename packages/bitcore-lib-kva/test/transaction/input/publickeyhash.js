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
var Networks = bitcore.Networks;
var Signature = bitcore.crypto.Signature;

describe('PublicKeyHashInput', function() {

  var privateKey = new PrivateKey('Mcz2kdVVjo9JLL96DMYm63HeVJsKy94hKn5Wr6agsyUBjqe5HvNw');
  var publicKey = privateKey.publicKey;
  var address = new Address(publicKey, Networks.livenet);
  var witnessAddress = new Address(publicKey, Networks.livenet, Address.PayToWitnessPublicKeyHash);
  var wrappedAddress = new Address(publicKey, Networks.livenet, Address.PayToScriptHash);

  var output = {
    address: 'VKeQ5By9ZWKVC6b3c272UAv5fok62DH4sG',
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(address),
    satoshis: 1000000
  };

  var witnessOutput = {
    address: 'kva1qnp7n05pss40cgkesk2wh5mul6uw0k4le09r9zd',
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(witnessAddress),
    satoshis: 1000000
  };

  var wrappedOutput = {
    address: 'VDe3CLKB4E6ViYzzqMHx1caguuPRuw7R7r',
    txId: '66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140',
    outputIndex: 0,
    script: new Script(wrappedAddress),
    satoshis: 1000000
  };

  it('can count missing signatures', function() {
    var transaction = new Transaction()
      .from(output)
      .to(address, 1000000);
    var input = transaction.inputs[0];

    input.isFullySigned().should.equal(false);
    transaction.sign(privateKey);
    input.isFullySigned().should.equal(true);
  });
  it('it\'s size can be estimated', function() {
    var transaction = new Transaction()
      .from(output)
      .to(address, 1000000);
    var input = transaction.inputs[0];
    input._estimateSize().should.equal(107);
  });
  it('it\'s signature can be removed', function() {
    var transaction = new Transaction()
      .from(output)
      .to(address, 1000000);
    var input = transaction.inputs[0];

    transaction.sign(privateKey);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });
  it('returns an empty array if private key mismatches', function() {
    var transaction = new Transaction()
      .from(output)
      .to(address, 1000000);
    var input = transaction.inputs[0];
    var signatures = input.getSignatures(transaction, new PrivateKey(), 0);
    signatures.length.should.equal(0);
  });

  describe('P2WPKH', function () {
    it('can count missing signatures', function() {
      var transaction = new Transaction()
        .from(witnessOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];

      input.isFullySigned().should.equal(false);
      transaction.sign(privateKey);
      input.isFullySigned().should.equal(true);
    });
    it('it\'s size can be estimated', function() {
      var transaction = new Transaction()
        .from(witnessOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      input._estimateSize().should.equal(26.75);
    });
    it('it\'s signature can be removed', function() {
      var transaction = new Transaction()
        .from(witnessOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];

      transaction.sign(privateKey);
      input.clearSignatures();
      input.isFullySigned().should.equal(false);
    });
    it('returns an empty array if private key mismatches', function() {
      var transaction = new Transaction()
        .from(witnessOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var signatures = input.getSignatures(transaction, new PrivateKey(), 0);
      signatures.length.should.equal(0);
    });
    it('will get the scriptCode', function() {
      var transaction = new Transaction()
        .from(wrappedOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var scriptCode = input.getScriptCode(publicKey);
      scriptCode.toString('hex').should.equal('1976a91452262bd0a01c920c3d08d57ad44490162da9341688ac');
    });
    it('will get the satoshis buffer', function() {
      var transaction = new Transaction()
        .from(wrappedOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var satoshisBuffer = input.getSatoshisBuffer();
      satoshisBuffer.toString('hex').should.equal('40420f0000000000');
    });
  });

  describe('P2SH-wrapped-P2WPKH', function () {
    it('can count missing signatures', function() {
      var transaction = new Transaction()
        .from(wrappedOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];

      input.isFullySigned().should.equal(false);
      transaction.sign(privateKey);
      input.isFullySigned().should.equal(true);
    });
    it('it\'s size can be estimated', function() {
      var transaction = new Transaction()
        .from(wrappedOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      input._estimateSize().should.equal(48.75);
    });
    it('it\'s signature can be removed', function() {
      var transaction = new Transaction()
        .from(wrappedOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];

      transaction.sign(privateKey);
      input.clearSignatures();
      input.isFullySigned().should.equal(false);
    });
    it('returns an empty array if private key mismatches', function() {
      var transaction = new Transaction()
        .from(wrappedOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var signatures = input.getSignatures(transaction, new PrivateKey(), 0);
      signatures.length.should.equal(0);
    });
    it('will get the scriptCode', function() {
      var transaction = new Transaction()
        .from(wrappedOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var scriptCode = input.getScriptCode(publicKey);
      scriptCode.toString('hex').should.equal('1976a91452262bd0a01c920c3d08d57ad44490162da9341688ac');
    });
    it('will get the satoshis buffer', function() {
      var transaction = new Transaction()
        .from(wrappedOutput)
        .to(address, 1000000);
      var input = transaction.inputs[0];
      var satoshisBuffer = input.getSatoshisBuffer();
      satoshisBuffer.toString('hex').should.equal('40420f0000000000');
    });
  });
});
