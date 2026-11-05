import gearth.protocol.HPacket;
import gearth.extensions.parsers.stuffdata.*;
import gearth.extensions.parsers.HFloorItem;
import gearth.extensions.parsers.HWallItem;
import gearth.extensions.parsers.HInventoryItem;
import gearth.extensions.parsers.HFriend;
import java.util.HashMap;
import java.util.HexFormat;

// Produces wire bytes using the released beta-29 Java API.
public class JavaStuffOracle {
    static void emit(String name, IStuffData data) {
        HPacket packet = new HPacket(1);
        data.appendToPacket(packet);
        System.out.println(name + "=" + HexFormat.of().formatHex(packet.toBytes()));
    }
    public static void main(String[] args) {
        HashMap<String, String> map = new HashMap<>();
        map.put("state", "2");
        emit("legacy", new LegacyStuffData(13, 20, "1"));
        emit("map", new MapStuffData(13, 20, map));
        emit("strings", new StringArrayStuffData(13, 20, "a"));
        emit("vote", new VoteResultStuffData(13, 20, "x", 3));
        emit("empty", new EmptyStuffData(13, 20));
        emit("integers", new IntArrayStuffData(13, 20, new Integer[]{1, -2}));
        emit("highscore", new HighScoreStuffData(13, 20, "x", 1, 2, new HighScoreData(7, "Alice")));
        emit("crackable", new CrackableStuffData(13, 20, "z", 4, 5));

        HPacket floorInput = new HPacket(1);
        floorInput.appendInt(77).appendInt(-5).appendInt(3).appendInt(4).appendInt(2)
                .appendString("1.5").appendString("1.0").appendInt(9);
        new LegacyStuffData(2, 100, "3").appendToPacket(floorInput);
        floorInput.appendInt(-1).appendInt(2).appendInt(42).appendString("static");
        HPacket floorOutput = new HPacket(1);
        new HFloorItem(floorInput).appendToPacket(floorOutput);
        System.out.println("floor=" + HexFormat.of().formatHex(floorOutput.toBytes()));

        HPacket wallInput = new HPacket(1);
        wallInput.appendString("123").appendInt(456).appendString(":w=1,2 l=3,4 r")
                .appendString("hello").appendInt(-1).appendInt(2).appendInt(42);
        HPacket wallOutput = new HPacket(1);
        new HWallItem(wallInput).appendToPacket(wallOutput);
        System.out.println("wall=" + HexFormat.of().formatHex(wallOutput.toBytes()));

        HPacket inventoryInput = new HPacket(1);
        inventoryInput.appendInt(1).appendString("S").appendInt(2).appendInt(3).appendInt(1);
        new EmptyStuffData().appendToPacket(inventoryInput);
        inventoryInput.appendBoolean(true).appendBoolean(true).appendBoolean(false).appendBoolean(true)
                .appendInt(-1).appendBoolean(false).appendInt(9).appendString("slot").appendInt(7);
        HPacket inventoryOutput = new HPacket(1);
        new HInventoryItem(inventoryInput).appendToPacket(inventoryOutput);
        System.out.println("inventory=" + HexFormat.of().formatHex(inventoryOutput.toBytes()));

        HPacket friendInput = new HPacket(1);
        friendInput.appendInt(8).appendString("Bob").appendInt(1).appendBoolean(true).appendBoolean(false)
                .appendString("hr").appendInt(2).appendString("m").appendString("").appendString("")
                .appendBoolean(false).appendBoolean(true).appendBoolean(false).appendShort((short) 1);
        HPacket friendOutput = new HPacket(1);
        new HFriend(friendInput).appendToPacket(friendOutput);
        System.out.println("friend=" + HexFormat.of().formatHex(friendOutput.toBytes()));
    }
}
