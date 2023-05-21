package jp.co.soramitsu.crypto.ed25519.spec;

import static jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable.ED_25519;
import static jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable.ED_25519_CURVE_SPEC;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

/**
 * @author str4d
 */
public class EdDSANamedCurveTableTest {

  /**
   * Ensure curve names are case-inspecific
   */
  @Test
  public void curveNamesAreCaseInspecific() {
    EdDSANamedCurveSpec mixed = EdDSANamedCurveTable.getByName("Ed25519");
    EdDSANamedCurveSpec lower = EdDSANamedCurveTable.getByName("ed25519");
    EdDSANamedCurveSpec upper = EdDSANamedCurveTable.getByName("ED25519");

    assertThat(lower, is(equalTo(mixed)));
    assertThat(upper, is(equalTo(mixed)));
  }

  @Test
  public void testConstants() {
    EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(ED_25519);
    assertThat("Named curve and constant should match", spec, is(equalTo(ED_25519_CURVE_SPEC)));
  }
}
