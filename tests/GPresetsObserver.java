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
    private static final class FixtureFurniData extends furnidata.FurniDataTools {
        @Override public boolean isReady() { return true; }
        @Override public Integer getFloorTypeId(String name) { return "fixture_floor".equals(name) ? 1500 : "tile_stackmagic1".equals(name) ? 1550 : "wf_trg_fixture".equals(name) ? 1600 : -1; }
        @Override public Integer getWallTypeId(String name) { return -1; }
        @Override public String getFloorItemName(int id) { return id == 1550 ? "tile_stackmagic1" : id == 1600 ? "wf_trg_fixture" : "fixture_floor"; }
        @Override public String getWallItemName(int id) { return "fixture_wall"; }
    }

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
                    if (Files.deleteIfExists(state.resolveSibling("fixture-furnidata.trigger"))) {
                        javafx.application.Platform.runLater(() -> {
                            try {
                                java.lang.reflect.Field field = GPresets.class.getDeclaredField("furniDataTools");
                                field.setAccessible(true);
                                field.set(presets, new FixtureFurniData());
                                presets.noExportWiredCbx.setSelected(true);
                                presets.noExportFurniVariablesCbx.setSelected(true);
                                presets.noExportWallItemsCbx.setSelected(true);
                                presets.previewBeforeImportCbx.setSelected(false);
                                presets.useRoomFurniCbx.setSelected(false);
                                Files.writeString(state.resolveSibling("fixture-furnidata.ready"), "ready");
                            } catch (Exception error) {
                                throw new IllegalStateException("fixture furnidata setup failed", error);
                            }
                        });
                    }
                    if (Files.deleteIfExists(state.resolveSibling("enable-wired.trigger"))) {
                        javafx.application.Platform.runLater(() -> {
                            try {
                                presets.noExportWiredCbx.setSelected(false);
                                Files.writeString(state.resolveSibling("enable-wired.ready"), "ready");
                            } catch (Exception error) {
                                throw new IllegalStateException("fixture WIRED setup failed", error);
                            }
                        });
                    }
                    Path loadTrigger = state.resolveSibling("load-preset.trigger");
                    if (Files.exists(loadTrigger)) {
                        String presetName = Files.readString(loadTrigger);
                        Files.delete(loadTrigger);
                        var preset = extension.tools.presetconfig.PresetConfigUtils.loadPreset(presetName);
                        if (preset == null) throw new IllegalStateException("fixture preset could not be loaded");
                        String loaded = preset.getFurniture().stream()
                            .map(item -> item.getClassName() + ":" + item.getFurniId() + ":" +
                                item.getLocation().getX() + ":" + item.getLocation().getY() + ":" + item.getRotation())
                            .sorted().collect(Collectors.joining(","));
                        // Reset simulated prerequisites between independent relay sessions.
                        if (!"fixture_wired".equals(presetName)) {
                            presets.getCatalog().clear();
                            presets.getPermissions().clear();
                        }
                        presets.getImporter().setPresetConfig(preset);
                        Files.writeString(state.resolveSibling("import-status.txt"),
                            presets.getImporter().isReady() + ":" + presets.getImporter().getState());
                        var triggers = preset.getPresetWireds().getTriggers();
                        String wired = triggers.stream().map(trigger -> trigger.getWiredId() + ":" +
                            trigger.getOptions() + ":" + trigger.getStringConfig() + ":" + trigger.getItems())
                            .collect(Collectors.joining(","));
                        Files.writeString(state.resolveSibling("loaded-wired.txt"), wired);
                        Files.writeString(state.resolveSibling("loaded-preset.txt"), loaded);
                    }
                    if (Files.deleteIfExists(state.resolveSibling("request-catalog.trigger"))) {
                        javafx.application.Platform.runLater(() -> presets.loadBCClick(null));
                    }
                    if (Files.deleteIfExists(state.resolveSibling("request-inventory.trigger"))) {
                        javafx.application.Platform.runLater(() -> presets.loadInventoryClick(null));
                    }
                    if (presets.getInventory() != null) {
                        String ids = presets.getInventory().getInventoryItems().stream()
                            .map(item -> item.getPlacementId()).sorted()
                            .map(String::valueOf).collect(Collectors.joining(","));
                        Files.writeString(state, ids);
                    }
                    if (presets.getCatalog() != null && presets.getPermissions() != null && presets.getImporter() != null) {
                        Files.writeString(state.resolveSibling("wired-permission.txt"),
                            Boolean.toString(presets.getPermissions().canModifyWired()));
                        Files.writeString(state.resolveSibling("readiness.txt"),
                            presets.getCatalog().getState() + ":" + presets.getPermissions().canMoveFurni() + ":" + presets.getImporter().isReady());
                        Files.writeString(state.resolveSibling("import-state-live.txt"), presets.getImporter().getState().toString());
                        Object importer = presets.getImporter();
                        java.lang.reflect.Field lockField = importer.getClass().getDeclaredField("lock");
                        java.lang.reflect.Field idMap = importer.getClass().getDeclaredField("realFurniIdMap");
                        lockField.setAccessible(true);
                        idMap.setAccessible(true);
                        Object mapped;
                        synchronized (lockField.get(importer)) {
                            Object rawMap = idMap.get(importer);
                            mapped = rawMap instanceof java.util.Map<?, ?> ? ((java.util.Map<?, ?>) rawMap).get(1) : null;
                            java.lang.reflect.Field expected = importer.getClass().getDeclaredField("expectFurniDrops");
                            expected.setAccessible(true);
                            Files.writeString(state.resolveSibling("placement-diagnostics.txt"), rawMap + ":" + expected.get(importer));
                        }
                        Files.writeString(state.resolveSibling("placement-ack.txt"), mapped == null ? "" : mapped.toString());
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
                        String floorDetails = presets.getFloorState().getItems().stream()
                            .map(item -> item.getId() + ":" + item.getTile().getX() + ":" + item.getTile().getY())
                            .sorted().collect(Collectors.joining(","));
                        String wallDetails = presets.getFloorState().getWallItems().stream()
                            .map(item -> item.getId() + ":" + item.getState())
                            .sorted().collect(Collectors.joining(","));
                        Files.writeString(state.resolveSibling("floor-details.txt"), floorDetails);
                        Files.writeString(state.resolveSibling("wall-details.txt"), wallDetails);
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
