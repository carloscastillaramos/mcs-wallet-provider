import com.sun.source.util.JavacTask;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

/**
 * Verificación sintáctica con solo el JDK; NO sustituye Maven ni resuelve dependencias.
 * Ejemplo: java tools/JavaSyntaxCheck.java src/main/java src/test/java
 */
public class JavaSyntaxCheck {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) throw new IllegalArgumentException("Indicar directorios de fuentes");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("Se requiere JDK completo");
        var paths = new java.util.ArrayList<java.io.File>();
        for (String input : args) {
            try (Stream<Path> stream = Files.walk(Path.of(input))) {
                stream.filter(path -> path.toString().endsWith(".java"))
                        .forEach(path -> paths.add(path.toFile()));
            }
        }
        DiagnosticCollector<JavaFileObject> errors = new DiagnosticCollector<>();
        try (StandardJavaFileManager manager = compiler.getStandardFileManager(errors, null, null)) {
            Iterable<? extends JavaFileObject> units = manager.getJavaFileObjectsFromFiles(paths);
            JavacTask parser = (JavacTask) compiler.getTask(null, manager, errors,
                    List.of("-source", "21", "-proc:none"), null, units);
            parser.parse();
        }
        boolean failed = false;
        for (Diagnostic<? extends JavaFileObject> diagnostic : errors.getDiagnostics()) {
            if (diagnostic.getKind() == Diagnostic.Kind.ERROR) {
                failed = true;
                System.err.println(diagnostic);
            }
        }
        if (failed) System.exit(1);
        System.out.println("Sintaxis Java 21 OK: " + paths.size() + " archivos. "
                + "No verifica tipos, dependencias ni compilación Maven.");
    }
}
