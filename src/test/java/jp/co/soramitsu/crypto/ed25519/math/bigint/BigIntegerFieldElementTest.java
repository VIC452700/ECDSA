package jp.co.soramitsu.crypto.ed25519.math.bigint;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertThat;

import java.math.BigInteger;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;
import jp.co.soramitsu.crypto.ed25519.math.AbstractFieldElementTest;
import jp.co.soramitsu.crypto.ed25519.math.Field;
import jp.co.soramitsu.crypto.ed25519.math.FieldElement;
import jp.co.soramitsu.crypto.ed25519.math.MathUtils;
import org.junit.Test;

/**
 * @author str4d
 */
public class BigIntegerFieldElementTest extends AbstractFieldElementTest {

  private static final byte[] BYTES_ZERO = DatatypeConverter
      .parseHexBinary("0000000000000000000000000000000000000000000000000000000000000000");
  private static final byte[] BYTES_ONE = DatatypeConverter
      .parseHexBinary("0100000000000000000000000000000000000000000000000000000000000000");
  private static final byte[] BYTES_TEN = DatatypeConverter
      .parseHexBinary("0a00000000000000000000000000000000000000000000000000000000000000");

  private static final Field ed25519Field = new Field(
      256, // b
      DatatypeConverter
          .parseHexBinary("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
      new BigIntegerLittleEndianEncoding());

  private static final FieldElement ZERO = new BigIntegerFieldElement(ed25519Field,
      BigInteger.ZERO);
  private static final FieldElement ONE = new BigIntegerFieldElement(ed25519Field, BigInteger.ONE);
  private static final FieldElement TWO = new BigIntegerFieldElement(ed25519Field,
      BigInteger.valueOf(2));

  protected FieldElement getRandomFieldElement() {
    BigInteger r;
    Random rnd = new Random();
    do {
      r = new BigInteger(255, rnd);
    } while (r.compareTo(getQ()) >= 0);
    return new BigIntegerFieldElement(ed25519Field, r);
  }

  protected BigInteger toBigInteger(FieldElement f) {
    return ((BigIntegerFieldElement) f).bi;
  }

  protected BigInteger getQ() {
    return MathUtils.getQ();
  }

  protected Field getField() {
    return ed25519Field;
  }

  /**
   * Test method for {@link BigIntegerFieldElement#BigIntegerFieldElement(Field, BigInteger)}.
   */
  @Test
  public void testFieldElementBigInteger() {
    assertThat(new BigIntegerFieldElement(ed25519Field, BigInteger.ZERO).bi, is(BigInteger.ZERO));
    assertThat(new BigIntegerFieldElement(ed25519Field, BigInteger.ONE).bi, is(BigInteger.ONE));
    assertThat(new BigIntegerFieldElement(ed25519Field, BigInteger.valueOf(2)).bi,
        is(BigInteger.valueOf(2)));
  }

  /**
   * Test method for {@link FieldElement#toByteArray()}.
   */
  @Test
  public void testToByteArray() {
    byte[] zero = ZERO.toByteArray();
    assertThat(zero.length, is(equalTo(BYTES_ZERO.length)));
    assertThat(zero, is(equalTo(BYTES_ZERO)));

    byte[] one = ONE.toByteArray();
    assertThat(one.length, is(equalTo(BYTES_ONE.length)));
    assertThat(one, is(equalTo(BYTES_ONE)));

    byte[] ten = new BigIntegerFieldElement(ed25519Field, BigInteger.TEN).toByteArray();
    assertThat(ten.length, is(equalTo(BYTES_TEN.length)));
    assertThat(ten, is(equalTo(BYTES_TEN)));
  }

  // region isNonZero

  protected FieldElement getZeroFieldElement() {
    return ZERO;
  }

  protected FieldElement getNonZeroFieldElement() {
    return TWO;
  }

  // endregion

  /**
   * Test method for {@link FieldElement#equals(java.lang.Object)}.
   */
  @Test
  public void testEqualsObject() {
    assertThat(new BigIntegerFieldElement(ed25519Field, BigInteger.ZERO), is(equalTo(ZERO)));
    assertThat(new BigIntegerFieldElement(ed25519Field, BigInteger.valueOf(1000)),
        is(equalTo(new BigIntegerFieldElement(ed25519Field, BigInteger.valueOf(1000)))));
    assertThat(ONE, is(not(equalTo(TWO))));
  }

}
