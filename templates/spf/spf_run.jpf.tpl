target=@TARGET@
classpath=@CLASSPATH@

target.args=@SEED_B64@

native_classpath+=@HARNESS_OUT@

spf.target_method=SpfHarness.run([B)V
spf.out_dir=@OUT_DIR@
spf.seed.max_bytes=@SEED_LIMIT@

@LISTENER_LINE@
symbolic.method=SpfHarness.run(sym)
symbolic.arrays=@SYMBOLIC_ARRAYS@

vm.storage.class=nil
search.multiple_errors=true

search.depth_limit=50
symbolic.max_int=1024
symbolic.min_int=-1024

symbolic.dp=@DP@
symbolic.debug=true
symbolic.print=true

listener=SpfSeedDumperListener
