import test from 'ava';

import { KelvinWallet } from 'kelvinjs-usbhid';
import { trxCurrencyUtil } from '../src';
import { IArmadilloCommand, ISignTxRequest } from '../src/ICurrencyUtil';

async function send(command: IArmadilloCommand): Promise<string> {
  const device = new KelvinWallet();
  const [status, buffer] = device.send(command.commandId, command.payload);

  device.close();

  if (status !== 0) {
    throw Error(`error status code ${status}`);
  }

  return buffer.toString('hex');
}

let publicKey = '';
let address = '';
let toAddress = '';

test('prepareCommandGetPubkey(accountId = 1)', async t => {
  const command = trxCurrencyUtil.prepareCommandGetPubkey('testnet', 1);
  const response = await send(command);

  const toPublicKey = trxCurrencyUtil.parsePubkeyResponse({
    payload: Buffer.from(response, 'hex')
  });
  toAddress = trxCurrencyUtil.encodePubkeyToAddr('testnet', toPublicKey);

  t.is(toAddress, 'TKB7thq3aDS2gzqPfJPHj4g1KRSJbBCHzU');

  console.log(toAddress);
});

test('prepareCommandGetPubkey(accountId = 0)', async t => {
  const command = trxCurrencyUtil.prepareCommandGetPubkey('testnet', 0);
  const response = await send(command);

  publicKey = trxCurrencyUtil.parsePubkeyResponse({
    payload: Buffer.from(response, 'hex')
  });
  address = trxCurrencyUtil.encodePubkeyToAddr('testnet', publicKey);

  t.is(address, 'TQUauGLDR4tcvu8U71WJdnE5dy2tsLSgXb');

  console.log(address);
});

test('prepareCommandShowAddr()', async t => {
  const command = trxCurrencyUtil.prepareCommandShowAddr('testnet', 0);
  const response = await send(command);

  t.deepEqual(response, '0800');
});

test('getBalance()', async t => {
  const balance = await trxCurrencyUtil.getBalance('testnet', address);

  console.log(balance);

  t.pass();
});

test('getRecentHistory()', async t => {
  const schema = trxCurrencyUtil.getHistorySchema();
  const txList = await trxCurrencyUtil.getRecentHistory('testnet', address);

  for (let i = 0; i < txList.length && i < 10; i++) {
    const tx = txList[i];
    for (const field of schema) {
      console.log(field.label, ':', tx[field.key].value);
    }
    console.log();
  }

  t.pass();
});

test('sign & submit tx', async t => {
  const schema = trxCurrencyUtil.getPreparedTxSchema();
  const req: ISignTxRequest = {
    network: 'testnet',
    accountIndex: 0,
    toAddr: toAddress,
    fromPubkey: publicKey,
    amount: '100000'
  };
  const [command, txinfo] = await trxCurrencyUtil.prepareCommandSignTx(req);

  for (const field of schema) {
    console.log(field.label, ':', txinfo[field.key].value);
  }
  console.log();

  const walletRsp = await send(command);

  const signedTx = trxCurrencyUtil.buildSignedTx(req, command, {
    payload: Buffer.from(walletRsp, 'hex')
  });

  const txid = await trxCurrencyUtil.submitTransaction('testnet', signedTx);
  console.log(trxCurrencyUtil.getUrlForTx('testnet', txid));

  t.pass();
});
