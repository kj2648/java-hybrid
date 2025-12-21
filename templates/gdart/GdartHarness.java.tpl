import tools.aqua.concolic.Verifier;

public class GdartHarness {
  static {
    System.setProperty("file.encoding", "UTF-8");
    System.setProperty("sun.jnu.encoding", "UTF-8");
  }

  private static final int MAX_BYTES = @SEED_LIMIT@;

  private static int pickLen() {
    String s = System.getProperty("jfo.input_len", "");
    int n = MAX_BYTES;
    if (s != null && !s.isEmpty()) {
      try {
        n = Integer.parseInt(s.trim());
      } catch (NumberFormatException ignored) {
        n = MAX_BYTES;
      }
    }
    if (n < 1) n = 1;
    if (n > MAX_BYTES) n = MAX_BYTES;
    return n;
  }

  public static void main(String[] args) throws Exception {
    int n = pickLen();
    byte[] data = new byte[n];
    for (int i = 0; i < n; i++) {
      data[i] = Verifier.nondetByte();
    }
    @TARGET_CLASS@.fuzzerTestOneInput(data);
  }
}

