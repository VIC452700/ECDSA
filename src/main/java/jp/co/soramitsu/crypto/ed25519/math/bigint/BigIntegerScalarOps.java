package jp.co.soramitsu.crypto.ed25519.math.bigint;

import java.math.BigInteger;
import jp.co.soramitsu.crypto.ed25519.math.Field;
import jp.co.soramitsu.crypto.ed25519.math.ScalarOps;

public class BigIntegerScalarOps implements ScalarOps {

  private final BigInteger l;
  private final BigIntegerLittleEndianEncoding enc;

  public BigIntegerScalarOps(Field f, BigInteger l) {
    this.l = l;
    enc = new BigIntegerLittleEndianEncoding();
    enc.setField(f);
  }

  public byte[] reduce(byte[] s) {
    return enc.encode(enc.toBigInteger(s).mod(l));
  }

  public byte[] multiplyAndAdd(byte[] a, byte[] b, byte[] c) {
    return enc
        .encode(enc.toBigInteger(a).multiply(enc.toBigInteger(b)).add(enc.toBigInteger(c)).mod(l));
  }

}
