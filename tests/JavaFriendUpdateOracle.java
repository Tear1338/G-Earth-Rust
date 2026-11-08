import gearth.extensions.parsers.HFriend;
import gearth.protocol.HPacket;
import java.util.HexFormat;

public class JavaFriendUpdateOracle {
    public static void main(String[] args) {
        HPacket input = new HPacket(3);
        input.appendInt(1).appendInt(2).appendString("Friends").appendInt(2).appendInt(0);
        input.appendInt(8).appendString("Bob").appendInt(1).appendBoolean(true).appendBoolean(false)
            .appendString("hr").appendInt(2).appendString("m").appendString("").appendString("")
            .appendBoolean(false).appendBoolean(true).appendBoolean(false).appendShort((short) 1);
        input.appendInt(-1).appendInt(99);
        HFriend[] friends = HFriend.parseFromUpdate(input);
        int[] removed = HFriend.getRemovedFriendIdsFromUpdate(input);
        if (friends.length != 1 || friends[0].getId() != 8 || !"Friends".equals(friends[0].getCategoryName()) || removed.length != 1 || removed[0] != 99) {
            throw new AssertionError("unexpected Java friend update parsing");
        }
        System.out.println(HexFormat.of().formatHex(input.toBytes()));
    }
}
