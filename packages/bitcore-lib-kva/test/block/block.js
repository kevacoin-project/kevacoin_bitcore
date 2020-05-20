'use strict';

var bitcore = require('../..');
var BN = require('../../lib/crypto/bn');
var BufferReader = bitcore.encoding.BufferReader;
var BufferWriter = bitcore.encoding.BufferWriter;
var BlockHeader = bitcore.BlockHeader;
var Block = bitcore.Block;
var chai = require('chai');
var fs = require('fs');
var should = chai.should();
var Transaction = bitcore.Transaction;

// https://test-insight.bitpay.com/block/000000000b99b16390660d79fcc138d2ad0c89a0d044c4201a02bdf1f61ffa11
var dataRawBlockBuffer = fs.readFileSync('test/data/blk86756-testnet.dat');
var dataRawBlockBinary = fs.readFileSync('test/data/blk86756-testnet.dat', 'binary');
var dataJson = fs.readFileSync('test/data/blk86756-testnet.json').toString();
var data = require('../data/blk86756-testnet');
var dataBlocks = require('../data/bitcoind/blocks');

describe('Block', function() {
  var blockhex;
  var blockbuf;
  var bh;
  var txs = [];
  var json;
  var genesishex;
  var genesisbuf;
  var genesisidhex;
  var blockOneHex;
  var blockOneBuf;
  var blockOneId;

  before(function () {
    blockhex = '0000002071af515a23b0fb5b6e253ccc265b96d6badc9f78a9758e1180df4a3eb4e7c95c2760529b7b294af9893b79d2afc793038cdb9442e5bb908823dff83911624db23174bf5ed004031d803801004c0c00b1e8fdf5053d25214759f057aadc89773356a88cddbb7aa6347c28845594a4c48c497fe80c4c810031a66dc1f25e0c348b5fc33f4805b8a8579e8f069efcf216835d22a64a65384e3d0101020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff050380380100ffffffff0200743ba40b00000017a9145c0dc24a85eba314366fb128a8c9e68ed072a345870000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000'
    blockbuf = Buffer.from(blockhex, 'hex');
    bh = BlockHeader.fromBuffer(Buffer.from(data.blockheaderhex, 'hex'));
    txs = [];
    JSON.parse(dataJson).transactions.forEach(function(tx) {
      txs.push(new Transaction().fromObject(tx));
    });
    json = dataJson;

    genesishex = '01000000000000000000000000000000000000000000000000000000000000000000000030334df25e9c7067139436a69dde2e1bd3bb2aa9ab67f8cc094da22d984a10e6b0d11f5effff0f1e000000004c0a00b0a3fff0055d43c919f1fd29289331d9bd12c60f8fe77e63166a5e9abd32e1f229a6811d9c4aee08006fde02dc52066063e1985710d777c21ffc243b6f875aef808f58d30321feba09010101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d04ffff001d0104355468616e6b20596f75205361746f7368692036313239393720323032302d30312d31352031313a34303a3431203766333166343464ffffffff01e8030000000000001817a914676a24ba4bfadd458e5245b26fa57f9a62ca18508700000000';
    genesisbuf =  Buffer.from(genesishex, 'hex');
    genesisidhex = '70bd30ae775c691fc8a2b7d27f37279a4f505f877e3234105f22e963a618597c';
    blockOneHex = '000000207c5918a663e9225f1034327e875f504f9a27377fd2b7a2c81f695c77ae30bd7031f2e2b5c62c3c808ff4745bdfb8bdb861de7b955d0b1f2d3db489497cfc87b1f6d11f5effff0d1e010000004c0a00f6a3fff0057369eabbac099d0e54671c93a335040fa9012eaf2640cac9a2bdfaa8b87f337dbc801500d7d70c22258ae389377df4125511e89c946c29f09ecb88b0b701a0d914ff98b80101020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200743ba40b00000017a914d03b0c06f8db322a2365e41385f2c8f6f89eebe3870000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000';
    blockOneBuf = Buffer.from(blockOneHex, 'hex');
    blockOneId = 'e79de02adef6c362bbedc1e39cc45130e19bd4c03ff4140ba2b9e5700eb0d3a2';
  });

  it('should make a new block', function() {
    var b = Block(blockbuf);
    b.toBuffer().toString('hex').should.equal(blockhex);
  });

  it('should not make an empty block', function() {
    (function() {
      return new Block();
    }).should.throw('Unrecognized argument for Block');
  });

  describe('#constructor', function() {

    it('should set these known values', function() {
      var b = new Block({
        header: bh,
        transactions: txs
      });
      should.exist(b.header);
      should.exist(b.transactions);
    });

    it('should properly deserialize blocks', function() {
      dataBlocks.forEach(function(block) {
        var b = Block.fromBuffer(Buffer.from(block.data, 'hex'));
        b.transactions.length.should.equal(block.transactions);
      });
    });

  });

  describe('#fromRawBlock', function() {

    it('should instantiate from a raw block binary', function() {
      var x = Block.fromRawBlock(dataRawBlockBinary);
      x.header.version.should.equal(536870912);
      new BN(x.header.bits).toString('hex').should.equal('1d10def3');
    });

    it('should instantiate from raw block buffer', function() {
      var x = Block.fromRawBlock(dataRawBlockBuffer);
      x.header.version.should.equal(536870912);
      new BN(x.header.bits).toString('hex').should.equal('1d10def3');
    });

  });

  describe('#fromJSON', function() {

    it('should set these known values', function() {
      var block = Block.fromObject(JSON.parse(json));
      should.exist(block.header);
      should.exist(block.transactions);
    });

    it('should set these known values', function() {
      var block = new Block(JSON.parse(json));
      should.exist(block.header);
      should.exist(block.transactions);
    });

  });

  describe('#toJSON', function() {

    it('should recover these known values', function() {
      var block = Block.fromObject(JSON.parse(json));
      var b = block.toJSON();
      should.exist(b.header);
      should.exist(b.transactions);
    });

  });

  describe('#fromString/#toString', function() {

    it('should output/input a block hex string', function() {
      var b = Block.fromString(blockhex);
      b.toString().should.equal(blockhex);
    });

  });


  describe('#fromBufferReader', function() {

    it('should make a block from this known buffer', function() {
      var block = Block.fromBufferReader(BufferReader(blockbuf));
      block.toBuffer().toString('hex').should.equal(blockhex);
    });

  });

  describe('#toBuffer', function() {

    it('should recover a block from this known buffer', function() {
      var block = Block.fromBuffer(blockbuf);
      block.toBuffer().toString('hex').should.equal(blockhex);
    });

  });

  describe('#toBufferWriter', function() {

    it('should recover a block from this known buffer', function() {
      var block = Block.fromBuffer(blockbuf);
      block.toBufferWriter().concat().toString('hex').should.equal(blockhex);
    });

    it('doesn\'t create a bufferWriter if one provided', function() {
      var writer = new BufferWriter();
      var block = Block.fromBuffer(blockbuf);
      block.toBufferWriter(writer).should.equal(writer);
    });

  });

  describe('#toObject', function() {

    it('should recover a block from genesis block buffer', function() {
      /*
      var block = Block.fromBuffer(blockOneBuf);
      block.id.should.equal(blockOneId);
      block.toObject().should.deep.equal({
        header: {
          hash: '00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048',
          version: 1,
          prevHash: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
          merkleRoot: '0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098',
          time: 1231469665,
          bits: 486604799,
          nonce: 2573394689
        },
        transactions: [{
          hash: '0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098',
          version: 1,
          inputs: [{
            prevTxId: '0000000000000000000000000000000000000000000000000000000000000000',
            outputIndex: 4294967295,
            sequenceNumber: 4294967295,
            script: '04ffff001d0104'
          }],
          outputs: [{
            satoshis: 5000000000,
            script: '410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c' +
              '52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac'
          }],
          nLockTime: 0
        }]
      });
      */
    });

    it('roundtrips correctly', function() {
      var block = Block.fromBuffer(blockOneBuf);
      var obj = block.toObject();
      var block2 = Block.fromObject(obj);
      block2.toObject().should.deep.equal(block.toObject());
    });

  });

  describe('#_getHash', function() {

    it('should return the correct hash of the genesis block', function() {
      var block = Block.fromBuffer(genesisbuf);
      var blockhash = Buffer.from(Array.apply([], Buffer.from(genesisidhex, 'hex')).reverse());
      block._getHash().toString('hex').should.equal(blockhash.toString('hex'));
    });
  });

  describe('#id', function() {

    it('should return the correct id of the genesis block', function() {
      var block = Block.fromBuffer(genesisbuf);
      block.id.should.equal(genesisidhex);
    });
    it('"hash" should be the same as "id"', function() {
      var block = Block.fromBuffer(genesisbuf);
      block.id.should.equal(block.hash);
    });

  });

  describe('#inspect', function() {

    it('should return the correct inspect of the genesis block', function() {
      var block = Block.fromBuffer(genesisbuf);
      block.inspect().should.equal('<Block ' + genesisidhex + '>');
    });

  });

  describe('#merkleRoot', function() {

    it('should describe as valid merkle root', function() {
      var x = Block.fromRawBlock(dataRawBlockBinary);
      var valid = x.validMerkleRoot();
      valid.should.equal(true);
    });

    it('should describe as invalid merkle root', function() {
      var x = Block.fromRawBlock(dataRawBlockBinary);
      x.transactions.push(new Transaction());
      var valid = x.validMerkleRoot();
      valid.should.equal(false);
    });

    it('should get a null hash merkle root', function() {
      var x = Block.fromRawBlock(dataRawBlockBinary);
      x.transactions = []; // empty the txs
      var mr = x.getMerkleRoot();
      mr.should.deep.equal(Block.Values.NULL_HASH);
    });

  });

});
