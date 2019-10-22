import test from 'ava';

import { trxCurrencyUtil } from '.';

test('isValidNormAmount()', t => {
  const f = trxCurrencyUtil.isValidNormAmount;
  t.true(f('0'));
  t.true(f('100'));
  t.true(f('100.'));
  t.true(f('1.000000'));
  t.true(f('1.000001'));
  t.true(f('100000000000.000000'));

  t.false(f('.'));
  t.false(f('.0'));
  t.false(f('001'));
  t.false(f('-1'));
  t.false(f(' 123'));
  t.false(f('123\n'));
  t.false(f('1.1234567'));
  t.false(f('100000000000.000001'));
});

test('convertNormAmountToBaseAmount()', t => {
  const f = trxCurrencyUtil.convertNormAmountToBaseAmount;
  t.is(f('0'), '0');
  t.is(f('100'), '100000000');
  t.is(f('100.1234'), '100123400');
  t.is(f('100.123456'), '100123456');

  t.throws(() => f('100.1234567'), Error);
  t.throws(() => f('-100.1234'), Error);
});

test('convertBaseAmountToNormAmount()', t => {
  const f = trxCurrencyUtil.convertBaseAmountToNormAmount;
  t.is(f('0'), '0');
  t.is(f('100'), '0.0001');
  t.is(f('1000000'), '1');
  t.is(f('10000000'), '10');

  t.throws(() => f('10000000.1'), Error);
  t.throws(() => f('-10'), Error);
});

test('isValidAddr()', t => {
  const f = trxCurrencyUtil.isValidAddr;

  t.true(f('mainnet', 'TLrMD9WqMUFQbJRMTfdHiZ4j5CHXfnUyyA'));

  t.false(f('mainnet', '410000000000000000000000000000000000000000'));

  t.false(f('mainnet', ' TLrMD9WqMUFQbJRMTfdHiZ4j5CHXfnUyyA'));
});

test('encodePubkeyToAddr()', t => {
  const f = trxCurrencyUtil.encodePubkeyToAddr;

  t.is(
    f(
      'mainnet',
      '04a9666a5615cf02456de2f6965c5c03493e0c9c2e4f4b81735c0124a59aadd9d55a1edfdc14f142660388f78b2a8e0f79f9837cfdeaf62f8594a4dcb6d955cf92'
    ),
    'TQUauGLDR4tcvu8U71WJdnE5dy2tsLSgXb'
  );
});

test('fee options', async t => {
  t.throws(() => trxCurrencyUtil.isValidFeeOption('mainnet', ''), Error);
  t.throws(() => trxCurrencyUtil.getFeeOptionUnit(), Error);
  await t.throwsAsync(
    async () => await trxCurrencyUtil.getFeeOptions('mainnet'),
    Error
  );
});

test('prepareCommandSignTx()', async t => {
  const f = trxCurrencyUtil.prepareCommandSignTx;

  await t.throwsAsync(
    async () => {
      const req = {
        network: 'testnet',
        accountIndex: 0,
        toAddr: 'TQUauGLDR4tcvu8U71WJdnE5dy2tsLSgXb',
        fromPubkey:
          '04a9666a5615cf02456de2f6965c5c03493e0c9c2e4f4b81735c0124a59aadd9d55a1edfdc14f142660388f78b2a8e0f79f9837cfdeaf62f8594a4dcb6d955cf92',
        amount: '1.23'
      };
      await f(req);
    },
    {
      instanceOf: Error,
      message: 'Should not send to self: TQUauGLDR4tcvu8U71WJdnE5dy2tsLSgXb'
    }
  );
});
