import java.util.Arrays;

public class SpfHarness {
  static {
    System.setProperty("file.encoding", "UTF-8");
    System.setProperty("sun.jnu.encoding", "UTF-8");
  }

  private static final int MAX_BYTES = @SEED_LIMIT@;

  public static void run(byte[] data) {
    @TARGET_CLASS@.fuzzerTestOneInput(data);
  }

  private static int b64(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;
    return -1;
  }

  private static byte[] decodeBase64(String s) {
    if (s == null || s.isEmpty()) return new byte[0];
    int len = s.length();
    byte[] out = new byte[(len * 3) / 4 + 4];
    int outLen = 0;

    int[] quad = new int[4];
    int q = 0;
    for (int i = 0; i < len; i++) {
      int v = b64(s.charAt(i));
      if (v == -1) continue;
      quad[q++] = v;
      if (q != 4) continue;
      q = 0;

      int a = quad[0], b = quad[1], c = quad[2], d = quad[3];
      if (a < 0 || b < 0) break;

      int x = (a << 18) | (b << 12) | ((c > 0 ? c : 0) << 6) | (d > 0 ? d : 0);
      out[outLen++] = (byte) ((x >> 16) & 0xff);
      if (c == -2) break;
      out[outLen++] = (byte) ((x >> 8) & 0xff);
      if (d == -2) break;
      out[outLen++] = (byte) (x & 0xff);
      if (outLen >= MAX_BYTES) break;
    }
    if (outLen > MAX_BYTES) outLen = MAX_BYTES;
    return Arrays.copyOf(out, outLen);
  }

  public static void main(String[] args) throws Exception {
    byte[] data = (args != null && args.length > 0) ? decodeBase64(args[0]) : new byte[0];
    run(data);
  }
}

