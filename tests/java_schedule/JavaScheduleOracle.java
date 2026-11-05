import gearth.app.ui.subforms.scheduler.InteractableScheduleItem;
import gearth.app.services.scheduler.Interval;
import gearth.protocol.HMessage;

public class JavaScheduleOracle {
    public static void main(String[] args) {
        System.out.println(new InteractableScheduleItem(0, false, new Interval(0, 500), "{h:42}{s:\"bonjour\"}", HMessage.Direction.TOSERVER).stringify());
        System.out.println(new InteractableScheduleItem(1, true, new Interval(125, 1000), "[0][0][0][2][0][5]", HMessage.Direction.TOCLIENT).stringify());
    }
}
