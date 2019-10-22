"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const trongrid_1 = __importDefault(require("trongrid"));
const tronweb_1 = __importDefault(require("tronweb"));
const kelvinjs_protob_1 = require("kelvinjs-protob");
const crypto_1 = __importDefault(require("crypto"));
const secp256k1_1 = __importDefault(require("secp256k1"));
const bignumber_js_1 = __importDefault(require("bignumber.js"));
const tron_tx_pb_1 = require("kelvinjs-protob/dist/tron-tx_pb");
const mainnetProvider = new tronweb_1.default.providers.HttpProvider('https://api.trongrid.io/', 5000 // timeout
);
const testnetProvider = new tronweb_1.default.providers.HttpProvider('https://api.shasta.trongrid.io/', 5000 // timeout
);
const mainnet = {
    web: new tronweb_1.default({ fullHost: mainnetProvider }),
    grid: undefined
};
const testnet = {
    web: new tronweb_1.default({ fullHost: testnetProvider }),
    grid: undefined
};
mainnet.grid = new trongrid_1.default(mainnet.web);
testnet.grid = new trongrid_1.default(testnet.web);
function isNonNegativeInteger(x) {
    return typeof x === 'number' && Number.isSafeInteger(x) && x >= 0;
}
// Also acts as a guard (throws exception)
function getNetwork(network) {
    if (network === 'mainnet') {
        return mainnet;
    }
    else if (network === 'testnet') {
        return testnet;
    }
    throw new Error(`Invalid network ${network}`);
}
exports.trxCurrencyUtil = {
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
        return addr[0] !== '4' && tronweb_1.default.isAddress(addr);
    },
    // <= 10^11 TRX
    isValidNormAmount(amount) {
        if (!/^(0|[1-9][0-9]*)(\.[0-9]*)?$/.test(amount)) {
            return false;
        }
        const v = new bignumber_js_1.default(amount);
        return (!v.isNegative() &&
            v.isLessThanOrEqualTo('100000000000') &&
            v.decimalPlaces() <= 6);
    },
    convertNormAmountToBaseAmount(amount) {
        if (!exports.trxCurrencyUtil.isValidNormAmount(amount)) {
            throw Error(`not a valid norm amount: ${amount}`);
        }
        return new bignumber_js_1.default(amount).multipliedBy(new bignumber_js_1.default('1000000')).toString();
    },
    convertBaseAmountToNormAmount(amount) {
        const v = new bignumber_js_1.default(amount);
        if (!(v.isInteger() &&
            !v.isNegative() &&
            v.isLessThanOrEqualTo('100000000000000000'))) {
            throw Error(`not a valid base amount: ${amount}`);
        }
        return new bignumber_js_1.default(amount).dividedBy(new bignumber_js_1.default('1000000')).toString();
    },
    getUrlForAddr(network, addr) {
        getNetwork(network);
        if (!exports.trxCurrencyUtil.isValidAddr(network, addr)) {
            throw new Error(`Invalid address ${addr}`);
        }
        if (network === 'mainnet') {
            return `https://tronscan.org/#/address/${addr}`;
        }
        else {
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
        }
        else {
            return `https://shasta.tronscan.org/#/transaction/${txid}`;
        }
    },
    encodePubkeyToAddr(network, pubkey) {
        getNetwork(network);
        if (!/^04[0-9a-f]{128}$/.test(pubkey)) {
            throw Error('invalid input');
        }
        return tronweb_1.default.utils.crypto.getBase58CheckAddress(tronweb_1.default.utils.crypto.computeAddress(Buffer.from(pubkey, 'hex').slice(1)));
    },
    getBalance(network, addr) {
        return __awaiter(this, void 0, void 0, function* () {
            const n = getNetwork(network);
            if (!exports.trxCurrencyUtil.isValidAddr(network, addr)) {
                throw new Error(`Invalid address ${addr}`);
            }
            try {
                const balance = yield n.web.trx.getBalance(addr);
                return exports.trxCurrencyUtil.convertBaseAmountToNormAmount(balance.toString());
            }
            catch (err) {
                if ('code' in err && err.code === 'ECONNABORTED') {
                    throw new Error(`A timeout happend on url ${err.config.url}`);
                }
                throw new Error('unknown error');
            }
        });
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
    getRecentHistory(network, addr) {
        return __awaiter(this, void 0, void 0, function* () {
            const n = getNetwork(network);
            if (!exports.trxCurrencyUtil.isValidAddr(network, addr)) {
                throw new Error(`Invalid address ${addr}`);
            }
            const myAddrHex = tronweb_1.default.address.toHex(addr);
            // may fail or not return 200
            let data;
            try {
                const { data: dataField } = yield n.grid.account.getTransactions(addr);
                data = dataField;
            }
            catch (e) {
                throw new Error(e);
            }
            return data.map(d => {
                const { txID, raw_data: { contract } } = d;
                const outAmount = contract
                    .filter(c => c.type === 'TransferContract' &&
                    c.parameter.value.owner_address === myAddrHex)
                    .map(c => c.parameter.value.amount)
                    .reduce((acc, x) => acc + x, 0);
                const inAmount = contract
                    .filter(c => c.type === 'TransferContract' &&
                    c.parameter.value.to_address === myAddrHex)
                    .map(c => c.parameter.value.amount)
                    .reduce((acc, x) => acc + x, 0);
                const amount = inAmount - outAmount;
                let amountNorm;
                if (amount >= 0) {
                    amountNorm = exports.trxCurrencyUtil.convertBaseAmountToNormAmount('' + amount);
                }
                else {
                    amountNorm =
                        '-' + exports.trxCurrencyUtil.convertBaseAmountToNormAmount('' + -amount);
                }
                return {
                    hash: { value: txID, link: exports.trxCurrencyUtil.getUrlForTx(network, txID) },
                    date: { value: new Date(d.block_timestamp).toISOString() },
                    amount: {
                        value: amountNorm
                    }
                };
            });
        });
    },
    getFeeOptions(network) {
        return __awaiter(this, void 0, void 0, function* () {
            throw new Error('No fee options available');
        });
    },
    prepareCommandSignTx(req) {
        return __awaiter(this, void 0, void 0, function* () {
            // ---- Check ----
            const n = getNetwork(req.network);
            if (!(isNonNegativeInteger(req.accountIndex) && req.accountIndex <= 0x7fffffff)) {
                throw Error(`invalid accountIndex: ${req.accountIndex}`);
            }
            if (!exports.trxCurrencyUtil.isValidAddr(req.network, req.toAddr)) {
                throw new Error(`Invalid to address ${req.toAddr}`);
            }
            if (!exports.trxCurrencyUtil.isValidNormAmount(req.amount)) {
                throw new Error(`Invalid norm amount ${req.amount}`);
            }
            const fromAddr = exports.trxCurrencyUtil.encodePubkeyToAddr(req.network, req.fromPubkey);
            if (fromAddr === req.toAddr) {
                throw new Error(`Should not send to self: ${fromAddr}`);
            }
            if (typeof req.feeOpt !== 'undefined') {
                throw new Error('No fee options available');
            }
            // ---- Look up ----
            let tx;
            try {
                tx = yield n.web.transactionBuilder.sendTrx(req.toAddr, exports.trxCurrencyUtil.convertNormAmountToBaseAmount(req.amount), fromAddr);
            }
            catch (e) {
                throw new Error(e);
            }
            // ---- Build ----
            const msg = new kelvinjs_protob_1.Tron.TrxCommand.TrxSignTx();
            msg.setAmount(tx.raw_data.contract[0].parameter.value.amount);
            msg.setPathList([req.accountIndex + 0x80000000, 0, 0]);
            msg.setRefBlockBytes(Buffer.from(tx.raw_data.ref_block_bytes, 'hex'));
            msg.setRefBlockHash(Buffer.from(tx.raw_data.ref_block_hash, 'hex'));
            // Change expiration (default ~ 60 secs, not enough for hardware)
            msg.setExpiration(tx.raw_data.timestamp + 60 * 60 * 1000); // 60 mins
            msg.setTimestamp(tx.raw_data.timestamp);
            msg.setTo(Buffer.from(tx.raw_data.contract[0].parameter.value.to_address, 'hex').slice(1));
            const cmd = new kelvinjs_protob_1.Tron.TrxCommand();
            cmd.setSignTx(msg);
            const metadata = {
                from: { value: fromAddr },
                to: { value: req.toAddr },
                amount: { value: req.amount }
            };
            return [
                {
                    commandId: kelvinjs_protob_1.TRON_CMDID,
                    payload: Buffer.from(cmd.serializeBinary())
                },
                metadata
            ];
        });
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
        const m = kelvinjs_protob_1.Tron.TrxCommand.deserializeBinary(preparedTx.payload);
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
                                owner_address: Buffer.from(tronweb_1.default.utils.crypto.computeAddress(Buffer.from(req.fromPubkey, 'hex').slice(1))).toString('hex'),
                                to_address: '41' + Buffer.from(msg.getTo_asU8()).toString('hex')
                            },
                            type_url: 'type.googleapis.com/protocol.TransferContract'
                        },
                        type: 'TransferContract'
                    }
                ],
                ref_block_bytes: Buffer.from(msg.getRefBlockBytes_asU8()).toString('hex'),
                ref_block_hash: Buffer.from(msg.getRefBlockHash_asU8()).toString('hex'),
                expiration: msg.getExpiration(),
                timestamp: msg.getTimestamp()
            },
            raw_data_hex: '',
            signature: ['']
        };
        const transfer = new kelvinjs_protob_1.TronTx.Tron_Raw.TransferContract();
        transfer.setAmount(msg.getAmount());
        transfer.setToAddress(Buffer.concat([Buffer.from('41', 'hex'), Buffer.from(msg.getTo_asU8())]));
        transfer.setOwnerAddress(Buffer.from(tronweb_1.default.utils.crypto.computeAddress(Buffer.from(req.fromPubkey, 'hex').slice(1))));
        const anyContract = new kelvinjs_protob_1.TronTx.Tron_Raw.Any();
        anyContract.setTypeUrl('type.googleapis.com/protocol.TransferContract');
        anyContract.setValue(transfer.serializeBinary());
        const contract = new kelvinjs_protob_1.TronTx.Tron_Raw.Contract();
        contract.setType(tron_tx_pb_1.Tron_Raw.Contract.ContractType.TRANSFERCONTRACT);
        contract.setParameter(anyContract);
        const raw = new kelvinjs_protob_1.TronTx.Tron_Raw();
        raw.addContract(contract);
        raw.setRefBlockBytes(msg.getRefBlockBytes_asU8());
        raw.setRefBlockHash(msg.getRefBlockHash_asU8());
        raw.setTimestamp(msg.getTimestamp());
        raw.setExpiration(msg.getExpiration());
        const rawData = Buffer.from(raw.serializeBinary());
        tx.raw_data_hex = rawData.toString('hex');
        tx.txID = crypto_1.default
            .createHash('sha256')
            .update(rawData)
            .digest('hex');
        // Put signature
        // TODO: deseiralize may err due to wrong response from wallet
        const wrsp = kelvinjs_protob_1.Tron.TrxResponse.deserializeBinary(walletRsp.payload);
        const wsig = wrsp.getSig();
        if (typeof wsig === 'undefined') {
            const msgCase = wrsp.getMsgCase();
            if (msgCase === kelvinjs_protob_1.Tron.TrxResponse.MsgCase.ERROR) {
                throw Error(`unexpected walletRsp with Armadillo errorCode ${wrsp.getError()}`);
            }
            throw Error(`unexpected walletRsp payload: ${walletRsp.payload.toString('hex')}`);
        }
        const sig = Buffer.from(wsig.getSig_asU8());
        const recoveredPk = secp256k1_1.default.recover(Buffer.from(tx.txID, 'hex'), sig, 0);
        const recoveredPkUncompressed = secp256k1_1.default.publicKeyConvert(recoveredPk, false);
        if (recoveredPkUncompressed.equals(Buffer.from(req.fromPubkey, 'hex'))) {
            tx.signature = [`${sig.toString('hex')}00`];
        }
        else {
            tx.signature = [`${sig.toString('hex')}01`];
        }
        return JSON.stringify(tx);
    },
    submitTransaction(network, signedTx) {
        return __awaiter(this, void 0, void 0, function* () {
            const n = getNetwork(network);
            const tx = JSON.parse(signedTx);
            let result;
            try {
                result = yield n.web.trx.sendRawTransaction(tx);
            }
            catch (e) {
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
                throw new Error(`${result.code}: ` + Buffer.from(result.message, 'hex').toString());
            }
            if (typeof result.code === 'string') {
                throw new Error(result.code);
            }
            throw new Error('unknown error');
        });
    },
    prepareCommandGetPubkey(network, accountIndex) {
        getNetwork(network);
        if (!(isNonNegativeInteger(accountIndex) && accountIndex <= 0x7fffffff)) {
            throw Error(`invalid accountIndex: ${accountIndex}`);
        }
        const msg = new kelvinjs_protob_1.Tron.TrxCommand.TrxGetPub();
        msg.setPathList([0x80000000 + accountIndex, 0, 0]);
        const cmd = new kelvinjs_protob_1.Tron.TrxCommand();
        cmd.setGetPub(msg);
        return {
            commandId: kelvinjs_protob_1.TRON_CMDID,
            payload: Buffer.from(cmd.serializeBinary())
        };
    },
    parsePubkeyResponse(walletRsp) {
        const wrsp = kelvinjs_protob_1.Tron.TrxResponse.deserializeBinary(walletRsp.payload);
        const wpk = wrsp.getPk();
        if (typeof wpk === 'undefined') {
            const msgCase = wrsp.getMsgCase();
            if (msgCase === kelvinjs_protob_1.Tron.TrxResponse.MsgCase.ERROR) {
                throw Error(`unexpected walletRsp with Armadillo errorCode ${wrsp.getError()}`);
            }
            throw Error(`unexpected walletRsp payload: ${walletRsp.payload.toString('hex')}`);
        }
        return '04' + Buffer.from(wpk.getPubkey_asU8()).toString('hex');
    },
    prepareCommandShowAddr(network, accountIndex) {
        getNetwork(network);
        if (!(isNonNegativeInteger(accountIndex) && accountIndex <= 0x7fffffff)) {
            throw Error(`invalid accountIndex: ${accountIndex}`);
        }
        const cmd = new kelvinjs_protob_1.Tron.TrxCommand();
        const msg = new kelvinjs_protob_1.Tron.TrxCommand.TrxShowAddr();
        cmd.setShowAddr(msg);
        msg.setPathList([accountIndex + 0x80000000, 0, 0]);
        return {
            commandId: kelvinjs_protob_1.TRON_CMDID,
            payload: Buffer.from(cmd.serializeBinary())
        };
    }
};
exports.default = exports.trxCurrencyUtil;
