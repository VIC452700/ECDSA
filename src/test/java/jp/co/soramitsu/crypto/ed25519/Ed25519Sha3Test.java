package jp.co.soramitsu.crypto.ed25519;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import javax.xml.bind.DatatypeConverter;
import org.junit.Test;

public class Ed25519Sha3Test {

  private final byte[] message = "hello world".getBytes();
  private final byte[] privateKey = DatatypeConverter
      .parseHexBinary("0000000000000000000000000000000000000000000000000000000000000000");
  private final byte[] publicKey = DatatypeConverter
      .parseHexBinary("43eeb17f0bab10dd51ab70983c25200a1742d31b3b7b54c38c34d7b827b26eed");

  @Test
  public void sunnyDayScenario() {
    Ed25519Sha3 engine = new Ed25519Sha3();

    KeyPair keyPair = engine.generateKeypair(privateKey);
    byte[] signature = engine.rawSign(message, keyPair);

    assertTrue(engine.rawVerify(message, signature, keyPair.getPublic()));

    byte[] pubdata = keyPair.getPublic().getEncoded();
    byte[] privdata = keyPair.getPrivate().getEncoded();

    assertArrayEquals(pubdata, publicKey);
    assertArrayEquals(privdata, privateKey);

    EdDSAPublicKey pub = (EdDSAPublicKey) Ed25519Sha3.publicKeyFromBytes(pubdata);
    EdDSAPrivateKey priv = (EdDSAPrivateKey) Ed25519Sha3.privateKeyFromBytes(privdata);

    assertArrayEquals(pub.getEncoded(), Ed25519Sha3.publicKeyToBytes(keyPair.getPublic()));
    assertArrayEquals(priv.getEncoded(), Ed25519Sha3.privateKeyToBytes(keyPair.getPrivate()));
  }
}
