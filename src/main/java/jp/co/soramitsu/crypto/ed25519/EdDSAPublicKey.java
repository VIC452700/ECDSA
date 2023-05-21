package jp.co.soramitsu.crypto.ed25519;

import java.security.PublicKey;
import jp.co.soramitsu.crypto.ed25519.math.GroupElement;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec;
import lombok.EqualsAndHashCode;
import lombok.Getter;

/**
 * An EdDSA public key.
 */
@EqualsAndHashCode
@Getter
public class EdDSAPublicKey implements EdDSAKey, PublicKey {

  private static final long serialVersionUID = 9837459837498475L;
  private final GroupElement A;
  private final byte[] Abyte;
  private final EdDSAParameterSpec params;
  private GroupElement Aneg = null;

  public EdDSAPublicKey(EdDSAPublicKeySpec spec) {
    this.A = spec.getA();
    this.Abyte = this.A.toByteArray();
    this.params = spec.getParams();
  }

  @Override
  public String getAlgorithm() {
    return KEY_ALGORITHM;
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  @Override
  public byte[] getEncoded() {
    return this.Abyte;
  }

  public GroupElement getNegativeA() {
    // Only read Aneg once, otherwise read re-ordering might occur between here and return. Requires all GroupElement's fields to be final.
    GroupElement ourAneg = Aneg;
    if (ourAneg == null) {
      ourAneg = A.negate();
      Aneg = ourAneg;
    }
    return ourAneg;
  }
}
