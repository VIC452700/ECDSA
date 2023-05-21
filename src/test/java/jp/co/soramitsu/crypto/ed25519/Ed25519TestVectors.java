package jp.co.soramitsu.crypto.ed25519;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.xml.bind.DatatypeConverter;

public class Ed25519TestVectors {

  public static Collection<TestTuple> testCases = getTestData("/test.data.sha3");

  public static Collection<TestTuple> getTestData(String fileName) {
    List<TestTuple> testCases = new ArrayList<TestTuple>();
    BufferedReader file = null;
    try {
      InputStream is = Ed25519TestVectors.class.getResourceAsStream(fileName);
      if (is == null) {
        throw new IOException("Resource not found: " + fileName);
      }
      file = new BufferedReader(new InputStreamReader(is));
      String line;
      while ((line = file.readLine()) != null) {
        testCases.add(new TestTuple(line));
      }
    } catch (IOException e) {
      e.printStackTrace();
    } finally {
      if (file != null) {
        try {
          file.close();
        } catch (IOException ignored) {
        }
      }
    }
    return testCases;
  }

  public static class TestTuple {

    public static int numCases;
    public int caseNum;
    public byte[] seed;
    public byte[] pk;
    public byte[] message;
    public byte[] sig;

    public TestTuple(String line) {
      caseNum = ++numCases;
      String[] x = line.split(":");
      seed = DatatypeConverter.parseHexBinary(x[0].substring(0, 64)); // private key
      pk = DatatypeConverter.parseHexBinary(x[1]); // public key
      message = DatatypeConverter.parseHexBinary(x[2]);
      sig = DatatypeConverter.parseHexBinary(x[3].substring(0, 128));
    }
  }
}
