package gearth.app.ui.subforms.scheduler;

// The upstream Interval parser only needs this helper from the UI controller.
public class SchedulerController {
    public static boolean stringIsNumber(String value) {
        try {
            Integer.parseInt(value);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
