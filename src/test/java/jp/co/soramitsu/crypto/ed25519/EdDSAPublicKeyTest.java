package jp.co.soramitsu.crypto.ed25519;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import javax.xml.bind.DatatypeConverter;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec;
import org.junit.Test;

public class EdDSAPublicKeyTest {

  static final byte[] TEST_PUBKEY = DatatypeConverter.parseHexBinary(
      "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1");

  @Test
  public void testDecodeAndEncode() {
    // Decode
    EdDSAPublicKeySpec spec = new EdDSAPublicKeySpec(TEST_PUBKEY,
        EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
    EdDSAPublicKey keyIn = new EdDSAPublicKey(spec);

    // Encode
    EdDSAPublicKeySpec decoded = new EdDSAPublicKeySpec(
        keyIn.getA(),
        keyIn.getParams());
    EdDSAPublicKey keyOut = new EdDSAPublicKey(decoded);

    // Check
    assertThat(keyOut.getEncoded(), is(equalTo(
        TEST_PUBKEY
    )));
  }
}
