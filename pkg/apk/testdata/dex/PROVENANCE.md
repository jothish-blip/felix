# DEX Test Fixture Provenance

## Fixture: `sample_d8.dex`
- **Source**: Independently produced using standard OpenJDK 17 `javac` and Android SDK `d8`.
- **Compiler**: Google Android SDK D8 version `9.4.14` (build `b1e20dd52788b7a226f83e24d49d0a53108bc84a`).
- **Java Compiler**: Microsoft OpenJDK 17 `javac` (`-source 1.8 -target 1.8`).
- **Target Specification**: Dalvik Executable format (DEX version `035`).
- **Content**: Compiled `com.felix.sample.SampleApp` class defining constant string descriptors, API base URLs, S3 bucket identifiers, Google API key candidates, and bytecode methods.
- **License**: Apache 2.0 / Public Domain test fixture.
- **Purpose**: Verifies parser compatibility with real-world, toolchain-generated Dalvik Executables produced by the official Android SDK compiler rather than solely synthetic in-memory fixtures.
