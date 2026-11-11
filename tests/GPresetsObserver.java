import extension.GPresets;
import extension.GPresetsLauncher;
import extension.logger.Logger;
import gearth.extensions.ExtensionForm;
import gearth.extensions.ExtensionFormCreator;
import javafx.stage.Stage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Collectors;

/** Test-only launcher: observe the released extension without modifying it. */
public class GPresetsObserver extends GPresetsLauncher {
    @Override
    protected java.net.URL getFormResource() {
        return GPresetsLauncher.class.getResource("ui/gpresets.fxml");
    }

    @Override
    protected ExtensionForm createForm(Stage stage) throws Exception {
        ExtensionForm form = super.createForm(stage);
        GPresets presets = (GPresets) form;
        Path state = Path.of(System.getProperty("gearth.fixture.state"));
        Thread observer = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    if (presets.getInventory() != null) {
                        String ids = presets.getInventory().getInventoryItems().stream()
                            .map(item -> item.getPlacementId()).sorted()
                            .map(String::valueOf).collect(Collectors.joining(","));
                        Files.writeString(state, ids);
                    }
                    if (presets.getFloorState() != null) {
                        String floorIds = presets.getFloorState().getItems().stream()
                            .map(item -> item.getId()).sorted().map(String::valueOf)
                            .collect(Collectors.joining(","));
                        String wallIds = presets.getFloorState().getWallItems().stream()
                            .map(item -> item.getId()).sorted().map(String::valueOf)
                            .collect(Collectors.joining(","));
                        Files.writeString(state.resolveSibling("floor-state.txt"), floorIds);
                        Files.writeString(state.resolveSibling("wall-state.txt"), wallIds);
                    }
                } catch (Exception ignored) {
                    // The extension may update the inventory during this snapshot.
                }
                try { Thread.sleep(50); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            }
        }, "fixture-inventory-observer");
        observer.setDaemon(true);
        observer.start();
        return form;
    }

    public static void main(String[] args) {
        Logger.setVerboseConsole(true);
        Logger.enableFileOutput(Path.of("app.log"));
        ExtensionFormCreator.runExtensionForm(args, GPresetsObserver.class);
    }
}
