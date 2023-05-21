package jp.co.soramitsu.crypto.ed25519;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAGenParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSANamedCurveTable;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPrivateKeySpec;
import jp.co.soramitsu.crypto.ed25519.spec.EdDSAPublicKeySpec;

/**
 * Default keysize is 256 (Ed25519)
 */
public final class KeyPairGenerator extends KeyPairGeneratorSpi {

  private static final int DEFAULT_KEYSIZE = 256;
  private static final Hashtable<Integer, AlgorithmParameterSpec> edParameters = new Hashtable<Integer, AlgorithmParameterSpec>();

  static {
    edParameters
        .put(DEFAULT_KEYSIZE, new EdDSAGenParameterSpec(EdDSANamedCurveTable.ED_25519));
  }

  private EdDSAParameterSpec edParams;
  private SecureRandom random;
  private boolean initialized;

  public void initialize(int keysize, SecureRandom random) {
    AlgorithmParameterSpec edParams = edParameters.get(keysize);
    if (edParams == null) {
      throw new InvalidParameterException("unknown key type.");
    }

    try {
      initialize(edParams, random);
    } catch (InvalidAlgorithmParameterException e) {
      throw new InvalidParameterException("key type not configurable.");
    }
  }

  @Override
  public void initialize(AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidAlgorithmParameterException {
    if (params instanceof EdDSAParameterSpec) {
      edParams = (EdDSAParameterSpec) params;
    } else if (params instanceof EdDSAGenParameterSpec) {
      edParams = createNamedCurveSpec(((EdDSAGenParameterSpec) params).getName());
    } else {
      throw new InvalidAlgorithmParameterException("parameter object not a EdDSAParameterSpec");
    }

    this.random = random;
    initialized = true;
  }

  public KeyPair generateKeyPair() {
    if (!initialized) {
      initialize(DEFAULT_KEYSIZE, new SecureRandom());
    }

    byte[] seed = new byte[edParams.getCurve().getField().getb() / 8];
    random.nextBytes(seed);

    EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(seed, edParams);
    EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(privKey.getA(), edParams);

    return new KeyPair(new EdDSAPublicKey(pubKey), new EdDSAPrivateKey(privKey));
  }

  /**
   * Create an EdDSANamedCurveSpec from the provided curve name. The current implementation fetches
   * the pre-created curve spec from a table.
   *
   * @param curveName the EdDSA named curve.
   * @return the specification for the named curve.
   * @throws InvalidAlgorithmParameterException if the named curve is unknown.
   */
  protected EdDSANamedCurveSpec createNamedCurveSpec(String curveName)
      throws InvalidAlgorithmParameterException {
    EdDSANamedCurveSpec spec = EdDSANamedCurveTable.getByName(curveName);
    if (spec == null) {
      throw new InvalidAlgorithmParameterException("unknown curve name: " + curveName);
    }
    return spec;
  }
}
