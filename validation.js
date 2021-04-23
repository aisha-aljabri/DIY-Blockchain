'use strict';

const { createHash } = require('crypto');
const signing = require('./signing');
const sha512 = msg => createHash('sha512').update(msg).digest('hex');
const getSignatures = transactions => transactions.map(t => t.signature).join``;
/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = transaction => {
  // Enter your solution here
  if( signing.verify(transaction.source, transaction.source + transaction.recipient + transaction.amount, transaction.signature,) && transaction.amount >= 0 )
    return true
  else 
    return false
};

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 */
const isValidBlock = block => {
  // Your code here
  const {transactions: transaction, hash, nonce, previousHash} = block
  return transaction.every(isValidTransaction) && hash === sha512(previousHash + getSignatures(transaction) + nonce);

};

/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is a missing genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 */
const isValidChain = blockchain => {
  // Your code here
  const {blocks: [fBlock, ...blocks]} = blockchain
  return blocks.every(isValidBlock) && 
  fBlock.previousHash === null &&
  blocks.every(({previousHash}, i) => previousHash === [fBlock, ...blocks][i].hash);
};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = blockchain => {
  // Your code here
  const {blocks: [fBlock]} = blockchain
  fBlock.previousHash = 0;
};

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain
};
