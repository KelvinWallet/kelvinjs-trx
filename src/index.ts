import TronGrid from 'trongrid';
import TronWeb from 'tronweb';

import { Tron, TRON_CMDID, TronTx } from 'kelvinjs-protob';

import crypto from 'crypto';
import secp256k1 from 'secp256k1';

import bn from 'bignumber.js';

import { Tron_Raw } from 'kelvinjs-protob/dist/tron-tx_pb';
import { ICurrencyUtil, ITransaction } from './ICurrencyUtil';

interface ITron {
  web: any;
  grid: any;
}

const mainnetProvider = new TronWeb.providers.HttpProvider(
  'https://api.trongrid.io/',
  5000 // timeout
);

const testnetProvider = new TronWeb.providers.HttpProvider(
  'https://api.shasta.trongrid.io/',
  5000 // timeout
);

const mainnet: ITron = {
  web: new TronWeb({ fullHost: mainnetProvider }),
  grid: undefined
};

const testnet: ITron = {
  web: new TronWeb({ fullHost: testnetProvider }),
  grid: undefined
};

mainnet.grid = new TronGrid(mainnet.web);
testnet.grid = new TronGrid(testnet.web);

function isNonNegativeInteger(x: any): x is number {
  return typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
}

// Also acts as a guard (throws exception)
function getNetwork(network: string) {
  if (network === 'mainnet') {
    return mainnet;
  } else if (network === 'testnet') {
    return testnet;
  }

  throw new Error(`Invalid network ${network}`);
}

export const trxCurrencyUtil: ICurrencyUtil = {
  getSupportedNetworks() {
    return ['mainnet', 'testnet'];
  },

  getFeeOptionUnit() {
    throw new Error('No fee options available');
  },

  isValidFeeOption(network, feeOpt) {
    throw new Error('No fee options available');
  },

  isValidAddr(network, addr) {
    getNetwork(network);

    // because in isAddress(), '410000000000000000000000000000000000000000' is a valid address
    return addr[0] !== '4' && TronWeb.isAddress(addr);
  },

  // <= 10^11 TRX
  isValidNormAmount(amount) {
    if (!/^(0|[1-9][0-9]*)(\.[0-9]*)?$/.test(amount)) {
      return false;
    }

    const v = new bn(amount);
    return (
      !v.isNegative() &&
      v.isLessThanOrEqualTo('100000000000') &&
      v.decimalPlaces() <= 6
    );
  },

  convertNormAmountToBaseAmount(amount) {
    if (!trxCurrencyUtil.isValidNormAmount(amount)) {
      throw Error(`not a valid norm amount: ${amount}`);
    }

    return new bn(amount).multipliedBy(new bn('1000000')).toString();
  },

  convertBaseAmountToNormAmount(amount) {
    const v = new bn(amount);
    if (
      !(
        v.isInteger() &&
        !v.isNegative() &&
        v.isLessThanOrEqualTo('100000000000000000')
      )
    ) {
      throw Error(`not a valid base amount: ${amount}`);
    }
    return new bn(amount).dividedBy(new bn('1000000')).toString();
  },

  getUrlForAddr(network, addr) {
    getNetwork(network);

    if (!trxCurrencyUtil.isValidAddr(network, addr)) {
      throw new Error(`Invalid address ${addr}`);
    }

    if (network === 'mainnet') {
      return `https://tronscan.org/#/address/${addr}`;
    } else {
      return `https://shasta.tronscan.org/#/address/${addr}`;
    }
  },

  getUrlForTx(network, txid) {
    getNetwork(network);

    if (!/^[0-9a-f]{64}$/.test(txid)) {
      throw new Error(`Invalid txid ${txid}`);
    }

    if (network === 'mainnet') {
      return `https://tronscan.org/#/transaction/${txid}`;
    } else {
      return `https://shasta.tronscan.org/#/transaction/${txid}`;
    }
  },

  encodePubkeyToAddr(network, pubkey) {
    getNetwork(network);

    if (!/^04[0-9a-f]{128}$/.test(pubkey)) {
      throw Error('invalid input');
    }

    return TronWeb.utils.crypto.getBase58CheckAddress(
      TronWeb.utils.crypto.computeAddress(Buffer.from(pubkey, 'hex').slice(1))
    );
  },

  async getBalance(network, addr) {
    const n = getNetwork(network);

    if (!trxCurrencyUtil.isValidAddr(network, addr)) {
      throw new Error(`Invalid address ${addr}`);
    }

    try {
      const balance = await n.web.trx.getBalance(addr);
      return trxCurrencyUtil.convertBaseAmountToNormAmount(balance.toString());
    } catch (err) {
      if ('code' in err && err.code === 'ECONNABORTED') {
        throw new Error(`A timeout happend on url ${err.config.url}`);
      }
      throw new Error('unknown error');
    }
  },

  getHistorySchema() {
    return [
      { key: 'hash', label: 'Hash', format: 'hash' },
      { key: 'date', label: 'Date', format: 'date' },
      // { key: 'from', label: 'From', format: 'address' },
      // { key: 'to', label: 'To', format: 'address' },
      { key: 'amount', label: 'Amount', format: 'value' }
    ];
  },

  // Possible enhancements:
  //   1. sort, 2. don't aggregate history (so that we can show to/from addrs)
  // For tron, confirm/fail is almost instant, so we ignore the pending case
  async getRecentHistory(network, addr) {
    const n = getNetwork(network);

    if (!trxCurrencyUtil.isValidAddr(network, addr)) {
      throw new Error(`Invalid address ${addr}`);
    }

    const myAddrHex = TronWeb.address.toHex(addr);

    // may fail or not return 200
    let data;
    try {
      const { data: dataField } = await n.grid.account.getTransactions(addr);
      data = dataField;
    } catch (e) {
      throw new Error(e);
    }

    return data.map(d => {
      const {
        txID,
        raw_data: { contract }
      } = d;

      const outAmount = contract
        .filter(
          c =>
            c.type === 'TransferContract' &&
            c.parameter.value.owner_address === myAddrHex
        )
        .map(c => c.parameter.value.amount)
        .reduce((acc, x) => acc + x, 0);

      const inAmount = contract
        .filter(
          c =>
            c.type === 'TransferContract' &&
            c.parameter.value.to_address === myAddrHex
        )
        .map(c => c.parameter.value.amount)
        .reduce((acc, x) => acc + x, 0);

      const amount = inAmount - outAmount;
      let amountNorm: string;
      if (amount >= 0) {
        amountNorm = trxCurrencyUtil.convertBaseAmountToNormAmount('' + amount);
      } else {
        amountNorm =
          '-' + trxCurrencyUtil.convertBaseAmountToNormAmount('' + -amount);
      }

      return {
        hash: { value: txID, link: trxCurrencyUtil.getUrlForTx(network, txID) },
        date: { value: new Date(d.block_timestamp).toISOString() },
        amount: {
          value: amountNorm
        }
      };
    });
  },

  async getFeeOptions(network) {
    throw new Error('No fee options available');
  },

  async prepareCommandSignTx(req) {
    // ---- Check ----
    const n = getNetwork(req.network);

    if (
      !(
        isNonNegativeInteger(req.accountIndex) && req.accountIndex <= 0x7fffffff
      )
    ) {
      throw Error(`invalid accountIndex: ${req.accountIndex}`);
    }

    if (!trxCurrencyUtil.isValidAddr(req.network, req.toAddr)) {
      throw new Error(`Invalid to address ${req.toAddr}`);
    }

    if (!trxCurrencyUtil.isValidNormAmount(req.amount)) {
      throw new Error(`Invalid norm amount ${req.amount}`);
    }

    const fromAddr = trxCurrencyUtil.encodePubkeyToAddr(
      req.network,
      req.fromPubkey
    );

    if (fromAddr === req.toAddr) {
      throw new Error(`Should not send to self: ${fromAddr}`);
    }

    if (typeof req.feeOpt !== 'undefined') {
      throw new Error('No fee options available');
    }

    // ---- Look up ----
    let tx;
    try {
      tx = await n.web.transactionBuilder.sendTrx(
        req.toAddr,
        trxCurrencyUtil.convertNormAmountToBaseAmount(req.amount),
        fromAddr
      );
    } catch (e) {
      throw new Error(e);
    }

    // ---- Build ----
    const msg = new Tron.TrxCommand.TrxSignTx();

    msg.setAmount(tx.raw_data.contract[0].parameter.value.amount);
    msg.setPathList([req.accountIndex + 0x80000000, 0, 0]);
    msg.setRefBlockBytes(Buffer.from(tx.raw_data.ref_block_bytes, 'hex'));
    msg.setRefBlockHash(Buffer.from(tx.raw_data.ref_block_hash, 'hex'));

    // Change expiration (default ~ 60 secs, not enough for hardware)
    msg.setExpiration(tx.raw_data.timestamp + 60 * 60 * 1000); // 60 mins
    msg.setTimestamp(tx.raw_data.timestamp);
    msg.setTo(
      Buffer.from(
        tx.raw_data.contract[0].parameter.value.to_address,
        'hex'
      ).slice(1)
    );

    const cmd = new Tron.TrxCommand();
    cmd.setSignTx(msg);

    const metadata: ITransaction = {
      from: { value: fromAddr },
      to: { value: req.toAddr },
      amount: { value: req.amount }
    };

    return [
      {
        commandId: TRON_CMDID,
        payload: Buffer.from(cmd.serializeBinary())
      },
      metadata
    ];
  },

  getPreparedTxSchema() {
    return [
      { key: 'from', label: 'From', format: 'address' },
      { key: 'amount', label: 'Amount', format: 'value' },
      { key: 'to', label: 'To', format: 'address' }
    ];
  },

  buildSignedTx(req, preparedTx, walletRsp) {
    // TODO: We assume req and preparedTx are correct
    const m = Tron.TrxCommand.deserializeBinary(preparedTx.payload);
    const msg = m.getSignTx();

    if (!/^04[0-9a-f]{128}$/.test(req.fromPubkey)) {
      throw Error('invalid input');
    }

    const tx = {
      visible: false,
      txID: '',
      raw_data: {
        contract: [
          {
            parameter: {
              value: {
                amount: msg.getAmount(),
                owner_address: Buffer.from(
                  TronWeb.utils.crypto.computeAddress(
                    Buffer.from(req.fromPubkey, 'hex').slice(1)
                  )
                ).toString('hex'),
                to_address: '41' + Buffer.from(msg.getTo_asU8()).toString('hex')
              },
              type_url: 'type.googleapis.com/protocol.TransferContract'
            },
            type: 'TransferContract'
          }
        ],
        ref_block_bytes: Buffer.from(msg.getRefBlockBytes_asU8()).toString(
          'hex'
        ),
        ref_block_hash: Buffer.from(msg.getRefBlockHash_asU8()).toString('hex'),
        expiration: msg.getExpiration(),
        timestamp: msg.getTimestamp()
      },
      raw_data_hex: '',
      signature: ['']
    };

    const transfer = new TronTx.Tron_Raw.TransferContract();
    transfer.setAmount(msg.getAmount());
    transfer.setToAddress(
      Buffer.concat([Buffer.from('41', 'hex'), Buffer.from(msg.getTo_asU8())])
    );
    transfer.setOwnerAddress(
      Buffer.from(
        TronWeb.utils.crypto.computeAddress(
          Buffer.from(req.fromPubkey, 'hex').slice(1)
        )
      )
    );

    const anyContract = new TronTx.Tron_Raw.Any();
    anyContract.setTypeUrl('type.googleapis.com/protocol.TransferContract');
    anyContract.setValue(transfer.serializeBinary());

    const contract = new TronTx.Tron_Raw.Contract();
    contract.setType(Tron_Raw.Contract.ContractType.TRANSFERCONTRACT);
    contract.setParameter(anyContract);

    const raw = new TronTx.Tron_Raw();
    raw.addContract(contract);
    raw.setRefBlockBytes(msg.getRefBlockBytes_asU8());
    raw.setRefBlockHash(msg.getRefBlockHash_asU8());
    raw.setTimestamp(msg.getTimestamp());
    raw.setExpiration(msg.getExpiration());

    const rawData = Buffer.from(raw.serializeBinary());
    tx.raw_data_hex = rawData.toString('hex');

    tx.txID = crypto
      .createHash('sha256')
      .update(rawData)
      .digest('hex');

    // Put signature

    // TODO: deseiralize may err due to wrong response from wallet
    const wrsp = Tron.TrxResponse.deserializeBinary(walletRsp.payload);
    const wsig = wrsp.getSig();
    if (typeof wsig === 'undefined') {
      const msgCase = wrsp.getMsgCase();
      if (msgCase === Tron.TrxResponse.MsgCase.ERROR) {
        throw Error(
          `unexpected walletRsp with Armadillo errorCode ${wrsp.getError()}`
        );
      }
      throw Error(
        `unexpected walletRsp payload: ${walletRsp.payload.toString('hex')}`
      );
    }

    const sig = Buffer.from(wsig.getSig_asU8());

    const recoveredPk = secp256k1.recover(Buffer.from(tx.txID, 'hex'), sig, 0);
    const recoveredPkUncompressed = secp256k1.publicKeyConvert(
      recoveredPk,
      false
    );

    if (recoveredPkUncompressed.equals(Buffer.from(req.fromPubkey, 'hex'))) {
      tx.signature = [`${sig.toString('hex')}00`];
    } else {
      tx.signature = [`${sig.toString('hex')}01`];
    }

    return JSON.stringify(tx);
  },

  async submitTransaction(network, signedTx) {
    const n = getNetwork(network);
    const tx = JSON.parse(signedTx);

    let result;
    try {
      result = await n.web.trx.sendRawTransaction(tx);
    } catch (e) {
      throw new Error(e);
    }

    /*
    { result: true,
      transaction:
      { visible: false,
        txID:
          '28782188e56ac613f99be803040d5c9ae0e467797a6f0f88e5c188d0c20b0b00',
          .....
      }
    }

    OR

    { code: 'SIGERROR',
      message:
      '.....' }
    */

    if (typeof result.result !== 'undefined') {
      if (result.result) {
        return result.transaction.txID;
      }
    }

    if (typeof result.message !== 'undefined') {
      throw new Error(
        `${result.code}: ` + Buffer.from(result.message, 'hex').toString()
      );
    }

    if (typeof result.code === 'string') {
      throw new Error(result.code);
    }

    throw new Error('unknown error');
  },

  prepareCommandGetPubkey(network, accountIndex) {
    getNetwork(network);

    if (!(isNonNegativeInteger(accountIndex) && accountIndex <= 0x7fffffff)) {
      throw Error(`invalid accountIndex: ${accountIndex}`);
    }

    const msg = new Tron.TrxCommand.TrxGetPub();
    msg.setPathList([0x80000000 + accountIndex, 0, 0]);

    const cmd = new Tron.TrxCommand();
    cmd.setGetPub(msg);

    return {
      commandId: TRON_CMDID,
      payload: Buffer.from(cmd.serializeBinary())
    };
  },

  parsePubkeyResponse(walletRsp) {
    const wrsp = Tron.TrxResponse.deserializeBinary(walletRsp.payload);

    const wpk = wrsp.getPk();
    if (typeof wpk === 'undefined') {
      const msgCase = wrsp.getMsgCase();
      if (msgCase === Tron.TrxResponse.MsgCase.ERROR) {
        throw Error(
          `unexpected walletRsp with Armadillo errorCode ${wrsp.getError()}`
        );
      }
      throw Error(
        `unexpected walletRsp payload: ${walletRsp.payload.toString('hex')}`
      );
    }

    return '04' + Buffer.from(wpk.getPubkey_asU8()).toString('hex');
  },

  prepareCommandShowAddr(network, accountIndex) {
    getNetwork(network);

    if (!(isNonNegativeInteger(accountIndex) && accountIndex <= 0x7fffffff)) {
      throw Error(`invalid accountIndex: ${accountIndex}`);
    }

    const cmd = new Tron.TrxCommand();
    const msg = new Tron.TrxCommand.TrxShowAddr();
    cmd.setShowAddr(msg);
    msg.setPathList([accountIndex + 0x80000000, 0, 0]);

    return {
      commandId: TRON_CMDID,
      payload: Buffer.from(cmd.serializeBinary())
    };
  }
};

export default trxCurrencyUtil;
