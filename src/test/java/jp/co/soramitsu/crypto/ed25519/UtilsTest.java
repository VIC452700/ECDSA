package jp.co.soramitsu.crypto.ed25519;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.security.SecureRandom;
import javax.xml.bind.DatatypeConverter;
import org.hamcrest.core.IsEqual;
import org.junit.Test;

public class UtilsTest {

  private static final String hex1 = "3B6A27BCCEB6A42D62A3A8D02A6F0D73653215771DE243A63AC048A18B59DA29";
  private static final String hex2 = "47A3F5B71494BCD961F3A4E859A238D6EAF8E648746D2F56A89B5E236F98D45F";
  private static final String hex3 = "5FD396E4A2B5DC9078F57E3AB5A87C28FD128E5F78CC4A97F4122DC45F6E4BB9";
  private static final byte[] bytes1 = {59, 106, 39, -68, -50, -74, -92, 45, 98, -93, -88, -48, 42,
      111, 13, 115,
      101, 50, 21, 119, 29, -30, 67, -90, 58, -64, 72, -95, -117, 89, -38, 41};
  private static final byte[] bytes2 = {71, -93, -11, -73, 20, -108, -68, -39, 97, -13, -92, -24,
      89, -94, 56, -42,
      -22, -8, -26, 72, 116, 109, 47, 86, -88, -101, 94, 35, 111, -104, -44, 95};
  private static final byte[] bytes3 = {95, -45, -106, -28, -94, -75, -36, -112, 120, -11, 126, 58,
      -75, -88, 124, 40,
      -3, 18, -114, 95, 120, -52, 74, -105, -12, 18, 45, -60, 95, 110, 75, -71};

  /**
   * Test method for {@link jp.co.soramitsu.crypto.ed25519.Utils#equal(int, int)}.
   */
  @Test
  public void testIntEqual() {
    assertThat(Utils.equal(0, 0), is(1));
    assertThat(Utils.equal(1, 1), is(1));
    assertThat(Utils.equal(1, 0), is(0));
    assertThat(Utils.equal(1, 127), is(0));
    assertThat(Utils.equal(-127, 127), is(0));
    assertThat(Utils.equal(-42, -42), is(1));
    assertThat(Utils.equal(255, 255), is(1));
    assertThat(Utils.equal(-255, -256), is(0));
  }

  @Test
  public void equalsReturnsOneForEqualByteArrays() {
    final SecureRandom random = new SecureRandom();
    final byte[] bytes1 = new byte[32];
    final byte[] bytes2 = new byte[32];
    for (int i = 0; i < 100; i++) {
      random.nextBytes(bytes1);
      System.arraycopy(bytes1, 0, bytes2, 0, 32);
      assertThat(Utils.equal(bytes1, bytes2), IsEqual.equalTo(1));
    }
  }

  @Test
  public void equalsReturnsZeroForUnequalByteArrays() {
    final SecureRandom random = new SecureRandom();
    final byte[] bytes1 = new byte[32];
    final byte[] bytes2 = new byte[32];
    random.nextBytes(bytes1);
    for (int i = 0; i < 32; i++) {
      System.arraycopy(bytes1, 0, bytes2, 0, 32);
      bytes2[i] = (byte) (bytes2[i] ^ 0xff);
      assertThat(Utils.equal(bytes1, bytes2), IsEqual.equalTo(0));
    }
  }

  /**
   * Test method for {@link jp.co.soramitsu.crypto.ed25519.Utils#equal(byte[], byte[])}.
   */
  @Test
  public void testByteArrayEqual() {
    byte[] zero = new byte[32];
    byte[] one = new byte[32];
    one[0] = 1;

    assertThat(Utils.equal(zero, zero), is(1));
    assertThat(Utils.equal(one, one), is(1));
    assertThat(Utils.equal(one, zero), is(0));
    assertThat(Utils.equal(zero, one), is(0));
  }

  /**
   * Test method for {@link jp.co.soramitsu.crypto.ed25519.Utils#negative(int)}.
   */
  @Test
  public void testNegative() {
    assertThat(Utils.negative(0), is(0));
    assertThat(Utils.negative(1), is(0));
    assertThat(Utils.negative(-1), is(1));
    assertThat(Utils.negative(32), is(0));
    assertThat(Utils.negative(-100), is(1));
    assertThat(Utils.negative(127), is(0));
    assertThat(Utils.negative(-255), is(1));
  }

  /**
   * Test method for {@link jp.co.soramitsu.crypto.ed25519.Utils#bit(byte[], int)}.
   */
  @Test
  public void testBit() {
    assertThat(Utils.bit(new byte[]{0}, 0), is(0));
    assertThat(Utils.bit(new byte[]{8}, 3), is(1));
    assertThat(Utils.bit(new byte[]{1, 2, 3}, 9), is(1));
    assertThat(Utils.bit(new byte[]{1, 2, 3}, 15), is(0));
    assertThat(Utils.bit(new byte[]{1, 2, 3}, 16), is(1));
  }

  @Test
  public void hexToBytesReturnsCorrectByteArray() {
    assertThat(DatatypeConverter.parseHexBinary(hex1), IsEqual.equalTo(bytes1));
    assertThat(DatatypeConverter.parseHexBinary(hex2), IsEqual.equalTo(bytes2));
    assertThat(DatatypeConverter.parseHexBinary(hex3), IsEqual.equalTo(bytes3));
  }

  @Test
  public void bytesToHexReturnsCorrectHexString() {
    assertThat(DatatypeConverter.printHexBinary(bytes1), IsEqual.equalTo(hex1));
    assertThat(DatatypeConverter.printHexBinary(bytes2), IsEqual.equalTo(hex2));
    assertThat(DatatypeConverter.printHexBinary(bytes3), IsEqual.equalTo(hex3));
  }
}
