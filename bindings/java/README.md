# Java bindings for Keystone

Java bindings for the [Keystone](http://www.keystone-engine.org/) engine. Require JDK 10+.

## Sample

```java
    import keystone.Keystone;
    import keystone.KeystoneArchitecture;
    import keystone.KeystoneMode;
    import keystone.exceptions.AssembleFailedKeystoneException;
    
    public class App {
    
        public static void main(String[] args) {
            try (Keystone keystone = new Keystone(KeystoneArchitecture.X86, KeystoneMode.Mode32)) {
                try {
                    var result = keystone.assemble("INC ecx; DEC edx");
    
                    System.out.println("Number of statements encoded: " + result.getNumberOfStatements());
                    System.out.println("Base address: " + String.format("0x%08X", result.getAddress()));
                    System.out.print("Encoded bytes: ");
    
                    for (byte b: result.getMachineCode()) {
                        System.out.print(String.format("%X ", b));
                    }
    
                } catch (AssembleFailedKeystoneException e) {
                    System.out.println(e.getMessage());
                }
            }
        }
    }
```

Output:

> Number of statements encoded: 2  
Base address: 0x00000000  
Encoded bytes: 41 4A

Other samples are provided by the unit tests included with the library, which cover most of the code.

## Getting Started

1. Clone the repository locally.
2. Download or compile Keystone library and store it in the folder `src/main/resources/{os-prefix}/{keystone-lib}`, according [the specifications of JNA](https://java-native-access.github.io/jna/4.5.0/javadoc/index.html?com/sun/jna/NativeLibrary.html), or [the related unit test](https://github.com/java-native-access/jna/blob/7122be473e5f6179deb1c2b1c2fdeb77d8486fed/test/com/sun/jna/PlatformTest.java#L29).
3. Compile the Java bindings and issue the JAR using Maven `mvn package`. The unit tests are automatically while running the goal.
4. In your project, include `target/binding-java-{version}.jar` and [JNA](https://github.com/java-native-access/jna) using your favourite dependency manager, or include `target/binding-java-{version}-jar-with-dependencies.jar` that is packaged with JNA.

### Exception handling

Each operation that returns the native enumeration `ks_err` is wrapped in an instance of a subclass of `KeystoneException`, thrown when an error occurs. The Javadoc indicates the exceptions thrown by the Java bindings for Keystone.

### Garbage collection

Keystone library requires to open and close an handle, that must be collected once an instance of the class `Keystone` is disposed. For that purpose, the class implements the interface `AutoCloseable`. Nonetheless, the Java bindings also implement a cleaning mechanism that automatically collects the handle when the instance of the class is *phantom reachable*, meaning no memory leak can happen, even if the instance is not closed properly.
    
    
### Native function calls

The Java bindings for Keystone rely on [JNA Direct Mapping](https://github.com/java-native-access/jna/blob/master/www/DirectMapping.md) to improve the performances of native calls, approaching that of custom JNI.

## Found an issue or bug ?

Feel free to open a GitHub issue on [the official repository of Keystone](https://github.com/keystone-engine/keystone/issues) and ping the contributors.


## Contributors

Author: Jämes Ménétrey ([@ZenLulz](https://github.com/ZenLulz/)) 

Maintainers:

- Need some people here :) Feel free to contribute !

### Want to contribute ?

Hey you! Your help is more than welcome! Things to keep in mind when working on the Java bindings for Keystone:

- Think about the backward compatibility; while code refactoring is a good practice, changing entirely the API *may* result in struggles.
- Elaborate the unit tests that prove your code is working. Test all the paths of the newly-added functions/classes (IntelliJ can show some metrics using Coverage). Keep the code coverage high!
- Please; write the required Javadoc, so every developer has the chance to understand your code.
- Update the changelog with a summary of your changes.

#### Version notation

The version of the Java bindings for Keystone is indicated in the file Maven configuration file (`pom.xml`). The major, minor and incremental versions (w.x.y) match the version of the library Keystone that the bindings is developed with. The build number (the -z in w.x.y-z) is incremented for each newer version of the Java bindings. Please, don't forget to increment this version when you submit a pull request.

On the last commit for a pull request, please create a tag called `java-bindings-w.x.y-z`.

#### Pull request submission

Ping the contributors of the Java bindings when submitting a pull request, so your changes can be peer reviewed.
 

## License

The Java bindings for Keystone is open-sourced software licensed under the MIT license.
The license of the library Keystone may be different and is available [at the root of the repository of Keystone](https://github.com/keystone-engine/keystone).