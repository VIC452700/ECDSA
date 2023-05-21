package jp.co.soramitsu.crypto.ed25519.spec;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import javax.xml.bind.DatatypeConverter;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

/**
 * @author str4d
 */
public class EdDSAPrivateKeySpecTest {

  private static final byte[] ZERO_SEED = DatatypeConverter
      .parseHexBinary("0000000000000000000000000000000000000000000000000000000000000000");
  private static final byte[] ZERO_H = DatatypeConverter.parseHexBinary(
      "a856c35cab5063b9e7ea568314ec81c40ba577aae630de902004009e88f18d657bbdfdaaa0fc189c66c8d853248b6b118844d53f7d0ba11de0f3bfaf4cdd9b3f");
  private static final byte[] ZERO_PK = DatatypeConverter
      .parseHexBinary("43eeb17f0bab10dd51ab70983c25200a1742d31b3b7b54c38c34d7b827b26eed");

  private static final EdDSANamedCurveSpec ed25519 = EdDSANamedCurveTable
      .getByName(EdDSANamedCurveTable.ED_25519);

  @Rule
  public ExpectedException exception = ExpectedException.none();

  /**
   * Test method for {@link jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec#EdDSAPrivateKeySpec(byte[],
   * jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec)}.
   */
  @Test
  public void testEdDSAPrivateKeySpecFromSeed() {
    EdDSAPrivateKeySpec key = new EdDSAPrivateKeySpec(ZERO_SEED, ed25519);
    assertThat(key.getSeed(), is(equalTo(ZERO_SEED)));
    assertThat(key.getH(), is(equalTo(ZERO_H)));
    assertThat(key.getA().toByteArray(), is(equalTo(ZERO_PK)));
  }

  @Test
  public void incorrectSeedLengthThrows() {
    exception.expect(IllegalArgumentException.class);
    exception.expectMessage("seed length is wrong");
    new EdDSAPrivateKeySpec(new byte[2], ed25519);
  }

  /**
   * Test method for {@link jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec#EdDSAPrivateKeySpec(jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec,
   * byte[])}.
   */
  @Test
  public void testEdDSAPrivateKeySpecFromH() {
    EdDSAPrivateKeySpec key = new EdDSAPrivateKeySpec(ed25519, ZERO_H);
    assertThat(key.getSeed(), is(nullValue()));
    assertThat(key.getH(), is(equalTo(ZERO_H)));
    assertThat(key.getA().toByteArray(), is(equalTo(ZERO_PK)));
  }

  @Test
  public void incorrectHashLengthThrows() {
    exception.expect(IllegalArgumentException.class);
    exception.expectMessage("hash length is wrong");
    new EdDSAPrivateKeySpec(ed25519, new byte[2]);
  }
}
