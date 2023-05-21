package jp.co.soramitsu.crypto.ed25519;

import java.security.PrivateKey;
import jp.co.soramitsu.crypto.ed25519.math.GroupElement;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec;
import lombok.EqualsAndHashCode;
import lombok.Getter;

/**
 * An EdDSA private key.
 */
@EqualsAndHashCode
@Getter
public class EdDSAPrivateKey implements EdDSAKey, PrivateKey {

  private static final long serialVersionUID = 23495873459878957L;
  private final byte[] seed;  // will be null if constructed from a spec which was directly constructed from H
  private final byte[] h;  // the hash of the seed
  private final byte[] a;  // the private key
  private final GroupElement A;  // the public key
  private final byte[] Abyte;  // the public key
  private final EdDSAParameterSpec params;

  public EdDSAPrivateKey(EdDSAPrivateKeySpec spec) {
    this.seed = spec.getSeed();
    this.h = spec.getH();
    this.a = spec.geta();
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

  public byte[] geta() {
    return a;
  }

  public GroupElement getA() {
    return this.A;
  }

  @Override
  public byte[] getEncoded() {
    return seed;
  }
}
