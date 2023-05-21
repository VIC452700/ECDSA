package jp.co.soramitsu.crypto.ed25519;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import javax.xml.bind.DatatypeConverter;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec;
import org.junit.Test;

public class EdDSAPrivateKeyTest {

  private static final byte[] TEST_PRIVKEY = DatatypeConverter.parseHexBinary(
      "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842");

  @Test
  public void testDecodeAndEncode() throws Exception {
    // Decode
    EdDSAPrivateKeySpec spec = new EdDSAPrivateKeySpec(TEST_PRIVKEY,
        EdDSANamedCurveTable.ED_25519_CURVE_SPEC);
    EdDSAPrivateKey keyIn = new EdDSAPrivateKey(spec);

    // Encode
    EdDSAPrivateKeySpec decoded = new EdDSAPrivateKeySpec(
        keyIn.getSeed(),
        keyIn.getH(),
        keyIn.geta(),
        keyIn.getA(),
        keyIn.getParams());
    EdDSAPrivateKey keyOut = new EdDSAPrivateKey(decoded);

    // Check
    assertThat(keyOut.getEncoded(), is(equalTo(TEST_PRIVKEY)));
  }
}
