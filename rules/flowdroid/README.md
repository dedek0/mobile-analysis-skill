# FlowDroid setup

FlowDroid is the sound interprocedural taint engine for Android (Java/Kotlin). It
complements Semgrep: Semgrep is fast and works on decompiled source, FlowDroid is
slower but tracks dataflow through lifecycle/callbacks, fields, and aliasing — the
cases an LLM (or a pattern rule) misses.

The taint engine (`scripts/taint_engine.py`) runs FlowDroid automatically when it
is configured; it skips it gracefully otherwise. Semgrep and the `taint-flow-analyst`
still run regardless.

## What you need

1. **A FlowDroid CLI.** Either:
   - a `flowdroid` binary on `PATH`, or
   - set `FLOWDROID_JAR=/path/to/soot-infoflow-cmd-<ver>-jar-with-dependencies.jar`.
     The jar is published on Maven Central
     (`org.soot-oss:soot-infoflow-cmd`); the `-jar-with-dependencies` classifier
     is the one that runs from `java -jar`.

2. **Android platform JARs.** Set `ANDROID_PLATFORMS=/path/to/android-platforms`
   — a directory that contains `android-<api>/android.jar` (e.g. `android-33/android.jar`),
   the layout produced by `sdkmanager --install "platforms;android-33"`.

3. **An APK or DEX** to analyze (pass it with `--apk`).

## Run it

```bash
# directly
java -jar "$FLOWDROID_JAR" -a app.apk -p "$ANDROID_PLATFORMS" \
    -s rules/flowdroid/SourcesAndSinks.txt

# or via the taint engine, which normalizes the output into findings/taint.jsonl
python3 scripts/taint_engine.py scan <decompiled-src-dir> engagement-<slug>/ \
    --engines semgrep,flowdroid --apk app.apk
```

## Notes / limitations

- `SourcesAndSinks.txt` in this directory is a minimal starting set. Extend it
  per target — FlowDroid is only as complete as its source/sink definitions.
- FlowDroid struggles with obfuscated code, reflection, and native (`.so`) flows;
  for those, fall back to the `taint-flow-analyst` reading the decompiled output.
- The CLI output format varies between FlowDroid versions; the engine's parser is
  intentionally lenient and maps recognized sinks back to `TNT-*` reference IDs.
