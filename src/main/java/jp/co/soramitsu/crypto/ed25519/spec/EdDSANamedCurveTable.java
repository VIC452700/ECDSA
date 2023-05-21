package jp.co.soramitsu.crypto.ed25519.spec;

import java.util.HashMap;
import java.util.Locale;
import javax.xml.bind.DatatypeConverter;
import jp.co.soramitsu.crypto.ed25519.math.Curve;
import jp.co.soramitsu.crypto.ed25519.math.Field;
import jp.co.soramitsu.crypto.ed25519.math.ed25519.Ed25519LittleEndianEncoding;
import jp.co.soramitsu.crypto.ed25519.math.ed25519.Ed25519ScalarOps;

/**
 * The named EdDSA curves.
 *
 * @author str4d
 */
public class EdDSANamedCurveTable {

  public static final String ED_25519 = "Ed25519";

  private static final Field ed25519field = new Field(
      256, // b
      DatatypeConverter
          .parseHexBinary("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // q
      new Ed25519LittleEndianEncoding());

  private static final Curve ed25519curve = new Curve(ed25519field,
      DatatypeConverter
          .parseHexBinary("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), // d
      ed25519field.fromByteArray(DatatypeConverter.parseHexBinary(
          "b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"))); // I

  public static final EdDSANamedCurveSpec ED_25519_CURVE_SPEC = new EdDSANamedCurveSpec(
      ED_25519,
      ed25519curve,
      "SHA3-512", // H
      new Ed25519ScalarOps(), // l
      ed25519curve.createPoint( // B
          DatatypeConverter
              .parseHexBinary("5866666666666666666666666666666666666666666666666666666666666666"),
          true)); // Precompute tables for B

  private static volatile HashMap<String, EdDSANamedCurveSpec> curves = new HashMap<String, EdDSANamedCurveSpec>();

  static {
    // RFC 8032
    defineCurve(ED_25519_CURVE_SPEC);
  }

  private static synchronized void putCurve(String name, EdDSANamedCurveSpec curve) {
    HashMap<String, EdDSANamedCurveSpec> newCurves = new HashMap<String, EdDSANamedCurveSpec>(
        curves);
    newCurves.put(name, curve);
    curves = newCurves;
  }

  public static void defineCurve(EdDSANamedCurveSpec curve) {
    putCurve(curve.getName().toLowerCase(Locale.ENGLISH), curve);
  }

  static void defineCurveAlias(String name, String alias) {
    EdDSANamedCurveSpec curve = curves.get(name.toLowerCase(Locale.ENGLISH));
    if (curve == null) {
      throw new IllegalStateException();
    }
    putCurve(alias.toLowerCase(Locale.ENGLISH), curve);
  }

  public static EdDSANamedCurveSpec getByName(String name) {
    return curves.get(name.toLowerCase(Locale.ENGLISH));
  }
}
