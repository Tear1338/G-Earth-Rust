import org.apache.maven.artifact.versioning.ComparableVersion;

public class JavaMavenOracle {
    public static void main(String[] args) {
        String[] versions = {
            "1", "1.0", "1.0.0", "1-0", "1.0-0", "1..0", "1-1", "1.1",
            "1.0.0.X1", "1.0.0-X2", "1-a", "1-a1", "1-alpha", "1-alpha1",
            "1-b", "1-b2", "1-beta", "1-m1", "1-milestone", "1-rc1", "1-cr1",
            "1-snapshot", "1-ga", "1-final", "1-release", "1-sp", "1-sp1",
            "1-z", "1-foo", "1-foo2", "1.foo.2", "1-foo-2", "1.2.0-rc1",
            "1.2.0", "1.2.0.0.1", "1.2.0-1", "1.2.0.1", "1.10", "1.9",
            "1.000000001", "1.999999999999999999999999999999", "2", "0.1.6",
            "0.1.6rc1", "0.1.6post1", "0.1.6.dev0", "1+metadata", "1_2"
        };
        for (String a : versions) {
            for (String b : versions) {
                int result = Integer.signum(new ComparableVersion(a).compareTo(new ComparableVersion(b)));
                System.out.println(a + "\t" + b + "\t" + result);
            }
        }
    }
}
