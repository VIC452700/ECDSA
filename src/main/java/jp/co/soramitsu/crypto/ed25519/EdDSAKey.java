package jp.co.soramitsu.crypto.ed25519;

import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec;

/**
 * Common interface for all EdDSA keys.
 *
 * @author str4d
 */
public interface EdDSAKey {

  /**
   * The reported key algorithm for all EdDSA keys
   */
  String KEY_ALGORITHM = "EdDSA/SHA3";

  /**
   * @return a parameter specification representing the EdDSA domain parameters for the key.
   */
  EdDSAParameterSpec getParams();
}
