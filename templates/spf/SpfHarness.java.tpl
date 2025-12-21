import java.util.Base64;
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

  private static byte[] decodeBase64(String s) {
    if (s == null || s.isEmpty()) return new byte[0];
    byte[] data;
    try {
      data = Base64.getDecoder().decode(s);
    } catch (IllegalArgumentException e) {
      return new byte[0];
    }
    if (data.length > MAX_BYTES) return Arrays.copyOf(data, MAX_BYTES);
    return data;
  }

  public static void main(String[] args) throws Exception {
    byte[] data = (args != null && args.length > 0) ? decodeBase64(args[0]) : new byte[0];
    run(data);
  }
}
