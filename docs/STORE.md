# Native extension store

The Extensions tab includes catalogue loading, text search, rating/alphabetical/date ordering and operating-system, client, framework and category filters. It uses beta-29's original sirjonasxx/G-ExtensionStore catalogue version 1.5.3. Outdated entries are optional. Source, readme, release and framework-installation links are available for each entry.

Install downloads and extracts the selected package on a worker. Archives, member counts and expanded bytes are bounded; absolute paths, traversal and symlinks are rejected. Failed extraction removes only its verified staging directory. Installation manifests record version, command and archive SHA-256. Downloads do not launch the package.

Updates install a new version beside the previous one. Installed versions have separate Launch and Uninstall controls. Launch expands the original port, filename and cookie placeholders and uses the one-use authenticated extension channel. Java entries use the configured Java runtime. Other framework runtimes must be installed separately. Runtime output appears in the extension console.

Uninstall verifies the manifest and resolved managed installation directory. It does not select other installed versions. This path does not migrate or delete older Java G-Earth installations.

Fixtures cover searching/filtering, chronological ordering, versioned installation, failed-extraction rollback and managed-directory deletion. CI parses a pinned 105-entry original catalogue and authenticates the actual Java API fixture through the store command launcher. Full Maven ComparableVersion edge cases, thumbnails, embedded readme rendering and all legacy store presentation details remain outside current parity.
