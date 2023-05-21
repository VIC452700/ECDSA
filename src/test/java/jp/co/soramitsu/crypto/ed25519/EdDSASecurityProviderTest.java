package jp.co.soramitsu.crypto.ed25519;

import static org.junit.Assert.assertNotNull;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class EdDSASecurityProviderTest {

  @Rule
  public ExpectedException exception = ExpectedException.none();

  @Test
  public void canGetInstancesWhenProviderIsPresent() throws Exception {
    Security.addProvider(new EdDSASecurityProvider());

    final String providerName = "EdDSA";
    assertNotNull(Security.getProvider(providerName));

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EdDSAKey.KEY_ALGORITHM, providerName);
    KeyFactory keyFac = KeyFactory.getInstance(EdDSAKey.KEY_ALGORITHM, providerName);
    Signature sgr = Signature.getInstance(EdDSAEngine.SIGNATURE_ALGORITHM, providerName);

    Security.removeProvider(providerName);

    assertNotNull(keyGen);
    assertNotNull(keyFac);
    assertNotNull(sgr);
  }
}
