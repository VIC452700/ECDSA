package jp.co.soramitsu.crypto.ed25519.spec;

import jp.co.soramitsu.crypto.ed25519.math.Curve;
import jp.co.soramitsu.crypto.ed25519.math.GroupElement;
import jp.co.soramitsu.crypto.ed25519.math.ScalarOps;

/**
 * EdDSA Curve specification that can also be referred to by name.
 *
 * @author str4d
 */
public class EdDSANamedCurveSpec extends EdDSAParameterSpec {

  private final String name;

  public EdDSANamedCurveSpec(String name, Curve curve,
      String hashAlgo, ScalarOps sc, GroupElement B) {
    super(curve, hashAlgo, sc, B);
    this.name = name;
  }

  public String getName() {
    return name;
  }
}
