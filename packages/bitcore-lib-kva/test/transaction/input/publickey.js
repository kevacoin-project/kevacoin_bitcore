'use strict';

var should = require('chai').should();
var bitcore = require('../../..');
var Transaction = bitcore.Transaction;
var PrivateKey = bitcore.PrivateKey;

describe('PublicKeyInput', function() {

  var utxo = {
    "txid": "491fd74bbedd4f497ee737dffb1d6877e2594681ef43c68b63fd5b990ae96374",
    "vout": 1,
    "address": "VJHSSznvTmDQwXhDv2WxftZP915oT9z4aD",
    "redeemScript": "001468439a6ae2319dce69ac8fa089a8620f28bc123b",
    "scriptPubKey": "a91453a24f4654c5aabc03dbd2c5d7c0a993886d3f7887",
    "amount": 50,
    "confirmations": 2,
    "spendable": true
  };

  // I know, I know - don't steal my money :-)
  var privateKey = PrivateKey.fromWIF('Mg9sFFgKXoUBj3bWnVCVKaEGXcU5x58Wn4RZk2CY3VRsS57DP7hn');
  var address = privateKey.toAddress('livenet', 'scripthash');
  utxo.address.should.equal(address.toString());

  var destKey = new PrivateKey();

  it('will correctly sign a publickey out transaction', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    tx.sign(privateKey);
    tx.inputs[0].script.toBuffer().length.should.be.above(0);
  });

  it('count can count missing signatures', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    input.isFullySigned().should.equal(false);
    tx.sign(privateKey);
    input.isFullySigned().should.equal(true);
  });

  it('it\'s size can be estimated', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    input._estimateSize().should.equal(48.75);
  });

  it('it\'s signature can be removed', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    tx.sign(privateKey);
    input.isFullySigned().should.equal(true);
    input.clearSignatures();
    input.isFullySigned().should.equal(false);
  });

  it('returns an empty array if private key mismatches', function() {
    var tx = new Transaction();
    tx.from(utxo);
    tx.to(destKey.toAddress(), 10000);
    var input = tx.inputs[0];
    var signatures = input.getSignatures(tx, new PrivateKey(), 0);
    signatures.length.should.equal(0);
  });

});
