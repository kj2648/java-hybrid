import gov.nasa.jpf.Config;
import gov.nasa.jpf.PropertyListenerAdapter;
import gov.nasa.jpf.search.Search;
import gov.nasa.jpf.symbc.numeric.PathCondition;
import gov.nasa.jpf.vm.MethodInfo;
import gov.nasa.jpf.vm.ThreadInfo;
import gov.nasa.jpf.vm.VM;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SpfSeedDumperListener extends PropertyListenerAdapter {
  private static final Pattern ARRAY_ELEM = Pattern.compile("^(\\[[A-Z]@[^\\[]+)\\[(\\d+)\\]$");

  private final String targetMethod;
  private final Path outDir;
  private final int maxBytes;
  private int written = 0;

  public SpfSeedDumperListener(Config conf) {
    this.targetMethod = conf.getString("spf.target_method", "SpfHarness.run([B)V");
    this.outDir = Paths.get(conf.getString("spf.out_dir", "spf_solutions"));
    this.maxBytes = conf.getInt("spf.seed.max_bytes", 4096);
    try {
      Files.createDirectories(outDir);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void propertyViolated(Search search) {
    dump(search.getVM(), "err");
  }

  @Override
  public void methodExited(VM vm, ThreadInfo currentThread, MethodInfo exitedMethod) {
    if (exitedMethod == null) return;
    if (!targetMethod.equals(exitedMethod.getFullName())) return;
    dump(vm, "exit");
  }

  private void dump(VM vm, String tag) {
    try {
      PathCondition pc = PathCondition.getPC(vm);
      if (pc == null) return;

      Map<String, Object> model = pc.solveWithValuation();
      if (model == null || model.isEmpty()) return;

      int length = -1;
      String base = null;
      int maxIndex = -1;
      for (Map.Entry<String, Object> e : model.entrySet()) {
        String k = e.getKey();
        if (k.endsWith("_length") && k.startsWith("[B@")) {
          Object v = e.getValue();
          if (v instanceof Number) {
            length = ((Number) v).intValue();
            base = k.substring(0, k.length() - "_length".length());
          }
        } else {
          Matcher m = ARRAY_ELEM.matcher(k);
          if (m.matches()) {
            String b = m.group(1);
            int idx = Integer.parseInt(m.group(2));
            if (idx > maxIndex) maxIndex = idx;
            if (base == null) base = b;
          }
        }
      }

      if (length < 0) {
        length = (maxIndex >= 0) ? (maxIndex + 1) : 0;
      }
      if (length < 0) length = 0;
      if (length > maxBytes) length = maxBytes;

      byte[] data = new byte[length];
      if (base != null) {
        for (Map.Entry<String, Object> e : model.entrySet()) {
          String k = e.getKey();
          Matcher m = ARRAY_ELEM.matcher(k);
          if (!m.matches()) continue;
          if (!base.equals(m.group(1))) continue;
          int idx = Integer.parseInt(m.group(2));
          if (idx < 0 || idx >= data.length) continue;
          Object v = e.getValue();
          if (v instanceof Number) {
            data[idx] = (byte) ((Number) v).intValue();
          }
        }
      }

      String name = String.format("%s_%06d_%s.bin", tag, written++, base == null ? "seed" : base.replaceAll("[^A-Za-z0-9_.-]+", "_"));
      Path out = outDir.resolve(name);
      try (FileOutputStream fos = new FileOutputStream(out.toFile())) {
        fos.write(data);
      }
    } catch (Throwable t) {
      System.err.println("[SpfSeedDumperListener] dump failed: " + t);
    }
  }
}

