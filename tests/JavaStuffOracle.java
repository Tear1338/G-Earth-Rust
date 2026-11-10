import gearth.protocol.HPacket;
import gearth.extensions.parsers.stuffdata.*;
import gearth.extensions.parsers.HFloorItem;
import gearth.extensions.parsers.HWallItem;
import gearth.extensions.parsers.HInventoryItem;
import gearth.extensions.parsers.HFriend;
import gearth.extensions.parsers.HUserProfile;
import gearth.extensions.parsers.HGroup;
import gearth.extensions.parsers.HEntity;
import gearth.extensions.parsers.HEntityType;
import gearth.extensions.parsers.HEntityUpdate;
import gearth.extensions.parsers.catalog.HCatalogPage;
import gearth.extensions.parsers.catalog.HCatalogIndex;
import gearth.extensions.parsers.navigator.HNavigatorSearchResult;
import gearth.extensions.parsers.navigator.HNavigatorRoom;
import gearth.extensions.parsers.forums.HCommentOverview;
import gearth.extensions.parsers.forums.HThreadState;
import gearth.extensions.parsers.forums.HThread;
import gearth.extensions.parsers.forums.HThreadOverview;
import gearth.extensions.parsers.forums.HForumOverview;
import gearth.extensions.parsers.forums.HForum;
import java.util.HashMap;
import java.util.HexFormat;

// Produces wire bytes using the released beta-29 Java API.
public class JavaStuffOracle {
    static void emit(String name, IStuffData data) {
        HPacket packet = new HPacket(1);
        data.appendToPacket(packet);
        System.out.println(name + "=" + HexFormat.of().formatHex(packet.toBytes()));
    }
    static void appendFriend(HPacket p, int id, int category, int relationship) {
        p.appendInt(id).appendString("Friend" + id).appendInt(1).appendBoolean(true).appendBoolean(false)
            .appendString("figure").appendInt(category).appendString("motto").appendString("").appendString("")
            .appendBoolean(false).appendBoolean(true).appendBoolean(false).appendShort((short)relationship);
    }
    static void appendCatalogChain(HPacket p, int depth) {
        p.appendBoolean(depth % 2 == 0).appendInt(depth).appendInt(100 + depth).appendString("Node" + depth).appendString("loc" + depth)
            .appendInt(1).appendInt(1000 + depth).appendInt(depth == 0 ? 0 : 1);
        if (depth > 0) appendCatalogChain(p, depth - 1);
    }
    static void appendEntityBase(HPacket p, int type) {
        p.appendInt(123).appendString("Name").appendString("Motto").appendString("Figure")
            .appendInt(7).appendInt(1).appendInt(2).appendString("3.5").appendInt(5).appendInt(type);
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

        int[] ownerIds = {17, 1, 17, 2};
        String[] ownerNames = {null, "Bob", "Final", "Carol"};
        HFloorItem[] floorCollection = new HFloorItem[ownerIds.length];
        HWallItem[] wallCollection = new HWallItem[ownerIds.length];
        for (int i = 0; i < ownerIds.length; i++) {
            floorCollection[i] = new HFloorItem(new HPacket(floorOutput.toBytes()));
            floorCollection[i].setOwnerId(ownerIds[i]);
            floorCollection[i].setOwnerName(ownerNames[i]);
            wallCollection[i] = new HWallItem(new HPacket(wallOutput.toBytes()));
            wallCollection[i].setOwnerId(ownerIds[i]);
            wallCollection[i].setOwnerName(ownerNames[i]);
        }
        HPacket floors = HFloorItem.constructPacket(floorCollection, 1);
        HPacket walls = HWallItem.constructPacket(wallCollection, 1);
        HFloorItem[] parsedFloors = HFloorItem.parse(floors);
        HWallItem[] parsedWalls = HWallItem.parse(walls);
        if (parsedFloors.length != 4 || parsedWalls.length != 4 || !parsedFloors[0].getOwnerName().equals("Final") || !parsedWalls[0].getOwnerName().equals("Final")) throw new AssertionError("furniture owner mapping");
        System.out.println("floor_collection=" + HexFormat.of().formatHex(floors.toBytes()));
        System.out.println("wall_collection=" + HexFormat.of().formatHex(walls.toBytes()));
        HPacket floorMissing = new HPacket(1);
        floorMissing.appendInt(0).appendInt(1);
        floorCollection[0].appendToPacket(floorMissing);
        HPacket wallMissing = new HPacket(1);
        wallMissing.appendInt(0).appendInt(1);
        wallCollection[0].appendToPacket(wallMissing);
        HFloorItem floorNoOwner = HFloorItem.parse(floorMissing)[0];
        HWallItem wallNoOwner = HWallItem.parse(wallMissing)[0];
        if (floorNoOwner.getOwnerName() != null || wallNoOwner.getOwnerName() != null) throw new AssertionError("missing furniture owner");
        try { HFloorItem.constructPacket(new HFloorItem[]{floorNoOwner}, 1); throw new AssertionError("expected null owner rejection"); }
        catch (NullPointerException expected) { }
        try { HWallItem.constructPacket(new HWallItem[]{wallNoOwner}, 1); throw new AssertionError("expected null owner rejection"); }
        catch (NullPointerException expected) { }
        System.out.println("floor_missing_owner=" + HexFormat.of().formatHex(floorMissing.toBytes()));
        System.out.println("wall_missing_owner=" + HexFormat.of().formatHex(wallMissing.toBytes()));

        HPacket inventoryInput = new HPacket(1);
        inventoryInput.appendInt(1).appendString("S").appendInt(2).appendInt(3).appendInt(1);
        new EmptyStuffData().appendToPacket(inventoryInput);
        inventoryInput.appendBoolean(true).appendBoolean(true).appendBoolean(false).appendBoolean(true)
                .appendInt(-1).appendBoolean(false).appendInt(9).appendString("slot").appendInt(7);
        HPacket inventoryOutput = new HPacket(1);
        new HInventoryItem(inventoryInput).appendToPacket(inventoryOutput);
        System.out.println("inventory=" + HexFormat.of().formatHex(inventoryOutput.toBytes()));

        for (String type : new String[]{"I", "S", "E", "B", "s"}) {
            for (int special = 1; special <= 23; special++) {
                HPacket input = new HPacket(1);
                input.appendInt(1).appendString(type).appendInt(2).appendInt(3).appendInt(special);
                new EmptyStuffData().appendToPacket(input);
                input.appendBoolean(true).appendBoolean(true).appendBoolean(false).appendBoolean(true)
                        .appendInt(-1).appendBoolean(false).appendInt(9);
                if (type.equalsIgnoreCase("S")) input.appendString("slot").appendInt(7);
                HPacket output = new HPacket(1);
                new HInventoryItem(input).appendToPacket(output);
                System.out.println("inventory_item_" + type + "_" + special + "=" + HexFormat.of().formatHex(output.toBytes()));
            }
        }
        HInventoryItem sampleInventory = new HInventoryItem(new HPacket(inventoryOutput.toBytes()));
        for (int size : new int[]{0, 1, 599, 600, 601, 1200, 1201}) {
            HInventoryItem[] items = new HInventoryItem[size];
            java.util.Arrays.fill(items, sampleInventory);
            HPacket[] pages = HInventoryItem.constructPackets(items, 44);
            for (int page = 0; page < pages.length; page++) {
                System.out.println("inventory_page_" + size + "_" + page + "=" + HexFormat.of().formatHex(pages[page].toBytes()));
                pages[page].setReadIndex(6);
                HInventoryItem[] parsed = HInventoryItem.parse(pages[page]);
                HPacket result = new HPacket(1);
                result.appendInt(parsed.length).appendInt(pages[page].getReadIndex());
                System.out.println("inventory_parse_" + size + "_" + page + "=" + HexFormat.of().formatHex(result.toBytes()));
            }
        }

        HPacket friendInput = new HPacket(1);
        friendInput.appendInt(8).appendString("Bob").appendInt(1).appendBoolean(true).appendBoolean(false)
                .appendString("hr").appendInt(2).appendString("m").appendString("").appendString("")
                .appendBoolean(false).appendBoolean(true).appendBoolean(false).appendShort((short) 1);
        HPacket friendOutput = new HPacket(1);
        new HFriend(friendInput).appendToPacket(friendOutput);
        System.out.println("friend=" + HexFormat.of().formatHex(friendOutput.toBytes()));

        HPacket friendUpdate = new HPacket(3);
        friendUpdate.appendInt(3).appendInt(2).appendString("Old").appendInt(7).appendString("Other").appendInt(2).appendString("New");
        friendUpdate.appendInt(5).appendInt(0); appendFriend(friendUpdate, 8, 2, 0);
        friendUpdate.appendInt(-1).appendInt(99).appendInt(5); appendFriend(friendUpdate, 9, 77, 3);
        friendUpdate.appendInt(1); appendFriend(friendUpdate, 10, 7, 4);
        friendUpdate.appendInt(-1).appendInt(100);
        friendUpdate.setReadIndex(10);
        HFriend[] updatedFriends = HFriend.parseFromUpdate(friendUpdate);
        HPacket friendSummary = new HPacket(1);
        friendSummary.appendInt(updatedFriends.length).appendInt(friendUpdate.getReadIndex());
        for (HFriend f : updatedFriends) {
            friendSummary.appendInt(f.getId()).appendBoolean(f.getCategoryName() != null);
            if (f.getCategoryName() != null) friendSummary.appendString(f.getCategoryName());
            friendSummary.appendInt(f.getRelationshipStatus() == null ? -1 : f.getRelationshipStatus().getId());
        }
        int[] removedFriends = HFriend.getRemovedFriendIdsFromUpdate(friendUpdate);
        friendSummary.appendInt(removedFriends.length);
        for (int id : removedFriends) friendSummary.appendInt(id);
        friendSummary.appendInt(friendUpdate.getReadIndex());
        if (updatedFriends.length != 3 || updatedFriends[2].getRelationshipStatus() != null || !"New".equals(updatedFriends[0].getCategoryName())) throw new AssertionError("friend update");
        try { updatedFriends[2].appendToPacket(new HPacket(1)); throw new AssertionError("expected invalid relationship rejection"); }
        catch (NullPointerException expected) { }
        System.out.println("friend_update_mixed=" + HexFormat.of().formatHex(friendUpdate.toBytes()));
        System.out.println("friend_update_summary=" + HexFormat.of().formatHex(friendSummary.toBytes()));
        HPacket negativeCategories = new HPacket(3); negativeCategories.appendInt(-1).appendInt(0);
        if (HFriend.parseFromUpdate(negativeCategories).length != 0) throw new AssertionError("negative categories");
        System.out.println("friend_negative_categories=" + HexFormat.of().formatHex(negativeCategories.toBytes()));
        HPacket negativeUpdates = new HPacket(3); negativeUpdates.appendInt(0).appendInt(-1);
        if (HFriend.parseFromUpdate(negativeUpdates).length != 0) throw new AssertionError("negative updates");
        System.out.println("friend_negative_updates=" + HexFormat.of().formatHex(negativeUpdates.toBytes()));
        HFriend normalFriend = new HFriend(new HPacket(friendOutput.toBytes()));
        normalFriend.setCategoryName("Friends");
        HPacket javaUpdate = HFriend.constructUpdatePacket(new HFriend[]{normalFriend}, 3);
        System.out.println("friend_construct_java=" + HexFormat.of().formatHex(javaUpdate.toBytes()));
        for (int size : new int[]{0, 1, 99, 100, 101, 200, 201}) {
            HFriend[] friends = new HFriend[size];
            java.util.Arrays.fill(friends, normalFriend);
            HPacket[] pages = HFriend.constructFragmentPackets(friends, 44);
            for (int page = 0; page < pages.length; page++) {
                System.out.println("friend_fragment_" + size + "_" + page + "=" + HexFormat.of().formatHex(pages[page].toBytes()));
                pages[page].setReadIndex(6);
                HFriend[] parsed = HFriend.parseFromFragment(pages[page]);
                HPacket result = new HPacket(1); result.appendInt(parsed.length).appendInt(pages[page].getReadIndex());
                System.out.println("friend_fragment_parse_" + size + "_" + page + "=" + HexFormat.of().formatHex(result.toBytes()));
            }
        }

        for (int flags = 0; flags < 8; flags++) {
            int groups = flags % 3;
            HPacket input = new HPacket(1);
            input.appendInt(123).appendString("Alice").appendString("Salut é").appendString("figure").appendString("2020-01-02")
                .appendInt(456).appendInt(78).appendBoolean((flags & 1) != 0).appendBoolean((flags & 2) != 0).appendBoolean((flags & 4) != 0).appendInt(groups);
            for (int i = 0; i < groups; i++) {
                input.appendInt(100 + i).appendString("Groupe" + i).appendString("Badge" + i).appendString("A" + i).appendString("B" + i)
                    .appendBoolean(i % 2 == 0).appendInt(200 + i).appendBoolean(i % 2 != 0);
            }
            input.appendInt(-7).appendBoolean((flags & 1) != 0);
            HUserProfile profile = new HUserProfile(input);
            HPacket normalized = new HPacket(1);
            normalized.appendInt(profile.getId()).appendString(profile.getUsername()).appendString(profile.getMotto()).appendString(profile.getFigure()).appendString(profile.getCreationDate())
                .appendInt(profile.getAchievementScore()).appendInt(profile.getFriendCount()).appendBoolean(profile.isFriend()).appendBoolean(profile.isRequestedFriend()).appendBoolean(profile.isOnline()).appendInt(profile.getGroups().length);
            for (HGroup group : profile.getGroups()) {
                normalized.appendInt(group.getId()).appendString(group.getName()).appendString(group.getBadgeCode()).appendString(group.getPrimaryColor()).appendString(group.getSecondaryColor())
                    .appendBoolean(group.isFavorite()).appendInt(group.getOwnerId()).appendBoolean(group.isHasForum());
            }
            normalized.appendInt(profile.getLastAccessSince()).appendBoolean(profile.isOpenProfile());
            if (profile.getGroups().length != groups || profile.isFriend() != ((flags & 1) != 0)) throw new AssertionError("profile flags");
            System.out.println("profile_" + flags + "=" + HexFormat.of().formatHex(input.toBytes()));
            System.out.println("profile_normalized_" + flags + "=" + HexFormat.of().formatHex(normalized.toBytes()));
        }
        HPacket invalidProfile = new HPacket(1);
        invalidProfile.appendInt(123).appendString("Alice").appendString("").appendString("").appendString("")
            .appendInt(0).appendInt(0).appendBoolean(false).appendBoolean(false).appendBoolean(false).appendInt(-1);
        try { new HUserProfile(invalidProfile); throw new AssertionError("expected negative group count rejection"); }
        catch (NegativeArraySizeException expected) { }
        System.out.println("profile_negative_groups=" + HexFormat.of().formatHex(invalidProfile.toBytes()));

        HPacket catalogIndex = new HPacket(1);
        catalogIndex.appendBoolean(true).appendInt(2).appendInt(3).appendString("root").appendString("loc")
                .appendInt(1).appendInt(99).appendInt(0).appendBoolean(true).appendString("NORMAL");
        HCatalogIndex parsedIndex = new HCatalogIndex(catalogIndex);
        if (parsedIndex.getRoot().getOfferIds().get(0) != 99 || !parsedIndex.isNewAdditionsAvailable()) throw new AssertionError("catalog index");
        System.out.println("catalog_index=" + HexFormat.of().formatHex(catalogIndex.toBytes()));

        HPacket catalogPage = new HPacket(1);
        catalogPage.appendInt(7).appendString("NORMAL").appendString("default").appendInt(0).appendInt(0)
                .appendInt(0).appendInt(-1).appendBoolean(false).appendInt(1).appendInt(0)
                .appendString("promo").appendString("img").appendInt(1).appendInt(25).appendInt(60);
        HCatalogPage parsedPage = new HCatalogPage(catalogPage);
        if (parsedPage.getFrontPageItems().get(0).getProductOfferId() != 25) throw new AssertionError("catalog page");
        System.out.println("catalog_page=" + HexFormat.of().formatHex(catalogPage.toBytes()));
        HPacket fullCatalog = new HPacket(1);
        fullCatalog.appendInt(7).appendString("NORMAL").appendString("catalog_layout").appendInt(2).appendString("image1").appendString("image2")
            .appendInt(2).appendString("texte é").appendString("text2").appendInt(2);
        fullCatalog.appendInt(101).appendString("offer").appendBoolean(true).appendInt(10).appendInt(20).appendInt(3).appendInt(40).appendBoolean(true).appendInt(4);
        fullCatalog.appendString("S").appendInt(1001).appendString("floor").appendInt(2).appendBoolean(true).appendInt(500).appendInt(17);
        fullCatalog.appendString("I").appendInt(1002).appendString("wall").appendInt(3).appendBoolean(false);
        fullCatalog.appendString("B").appendString("badge-code");
        fullCatalog.appendString("E").appendInt(1003).appendString("effect").appendInt(1).appendBoolean(false);
        fullCatalog.appendInt(2).appendBoolean(true).appendBoolean(false).appendString("preview");
        fullCatalog.appendInt(102).appendString("empty").appendBoolean(false).appendInt(0).appendInt(0).appendInt(0).appendInt(0).appendBoolean(false).appendInt(-1)
            .appendInt(0).appendBoolean(false).appendBoolean(true).appendString("");
        fullCatalog.appendInt(101).appendBoolean(true).appendInt(4);
        for (int type : new int[]{0, 1, 2, 99}) {
            fullCatalog.appendInt(type).appendString("promo" + type).appendString("img" + type).appendInt(type);
            if (type == 0) fullCatalog.appendString("page.path");
            if (type == 1) fullCatalog.appendInt(555);
            if (type == 2) fullCatalog.appendString("product-code");
            fullCatalog.appendInt(60 + type);
        }
        HCatalogPage fullPage = new HCatalogPage(fullCatalog);
        if (fullPage.getOffers().size() != 2 || fullPage.getOffers().get(0).getProducts().size() != 4 || !fullPage.getOffers().get(1).getProducts().isEmpty()
            || fullPage.getOffers().get(0).getProducts().get(0).getUniqueLimitedItemsLeft() != 17
            || !"badge-code".equals(fullPage.getOffers().get(0).getProducts().get(2).getExtraParam())
            || fullPage.getFrontPageItems().size() != 4 || !"product-code".equals(fullPage.getFrontPageItems().get(2).getProductCode())) throw new AssertionError("full catalog page");
        System.out.println("catalog_full=" + HexFormat.of().formatHex(fullCatalog.toBytes()));
        HPacket negativeCatalog = new HPacket(1);
        negativeCatalog.appendInt(7).appendString("NORMAL").appendString("default").appendInt(0).appendInt(0).appendInt(-1).appendInt(-1).appendBoolean(false).appendInt(-1);
        HCatalogPage negativePage = new HCatalogPage(negativeCatalog);
        if (!negativePage.getOffers().isEmpty() || !negativePage.getFrontPageItems().isEmpty()) throw new AssertionError("negative catalog lists");
        System.out.println("catalog_negative_lists=" + HexFormat.of().formatHex(negativeCatalog.toBytes()));
        HPacket invalidImages = new HPacket(1); invalidImages.appendInt(7).appendString("NORMAL").appendString("default").appendInt(-1);
        try { new HCatalogPage(invalidImages); throw new AssertionError("expected negative image count rejection"); }
        catch (NegativeArraySizeException expected) { }
        System.out.println("catalog_negative_images=" + HexFormat.of().formatHex(invalidImages.toBytes()));
        HPacket negativeCatalogIndex = new HPacket(1);
        negativeCatalogIndex.appendBoolean(true).appendInt(2).appendInt(3).appendString("root").appendString("loc").appendInt(-1).appendInt(-1).appendBoolean(false).appendString("NORMAL");
        HCatalogIndex negativeIndex = new HCatalogIndex(negativeCatalogIndex);
        if (!negativeIndex.getRoot().getOfferIds().isEmpty() || !negativeIndex.getRoot().getChildren().isEmpty()) throw new AssertionError("negative catalog index lists");
        System.out.println("catalog_index_negative_lists=" + HexFormat.of().formatHex(negativeCatalogIndex.toBytes()));
        HPacket catalogTree = new HPacket(1);
        catalogTree.appendBoolean(true).appendInt(10).appendInt(1).appendString("root").appendString("root.loc")
            .appendInt(2).appendInt(11).appendInt(12).appendInt(2);
        catalogTree.appendBoolean(false).appendInt(20).appendInt(2).appendString("child1").appendString("child1.loc")
            .appendInt(1).appendInt(21).appendInt(1);
        catalogTree.appendBoolean(true).appendInt(30).appendInt(3).appendString("grandchild").appendString("grand.loc")
            .appendInt(2).appendInt(31).appendInt(32).appendInt(0);
        catalogTree.appendBoolean(true).appendInt(40).appendInt(4).appendString("child2").appendString("child2.loc")
            .appendInt(0).appendInt(0).appendBoolean(true).appendString("NORMAL");
        HCatalogIndex parsedTree = new HCatalogIndex(catalogTree);
        var root = parsedTree.getRoot(); var first = root.getChildren().get(0); var grandchild = first.getChildren().get(0);
        HPacket treeSummary = new HPacket(1);
        treeSummary.appendInt(catalogTree.getReadIndex()).appendBoolean(root.isVisible()).appendInt(root.getOfferIds().size()).appendInt(root.getChildren().size())
            .appendBoolean(first.isVisible()).appendInt(first.getPageId()).appendInt(first.getOfferIds().get(0)).appendInt(grandchild.getPageId())
            .appendString(grandchild.getPageName()).appendInt(grandchild.getOfferIds().get(1)).appendInt(root.getChildren().get(1).getPageId());
        if (!parsedTree.isNewAdditionsAvailable() || grandchild.getPageId() != 3) throw new AssertionError("catalog tree");
        System.out.println("catalog_tree=" + HexFormat.of().formatHex(catalogTree.toBytes()));
        System.out.println("catalog_tree_summary=" + HexFormat.of().formatHex(treeSummary.toBytes()));
        for (int depth : new int[]{64, 65}) {
            HPacket chain = new HPacket(1); appendCatalogChain(chain, depth); chain.appendBoolean(false).appendString("NORMAL");
            HCatalogIndex parsed = new HCatalogIndex(chain);
            if (parsed.getRoot().getPageId() != 100 + depth) throw new AssertionError("catalog chain");
            System.out.println("catalog_tree_depth_" + depth + "=" + HexFormat.of().formatHex(chain.toBytes()));
        }

        HPacket navigatorInput = new HPacket(1);
        navigatorInput.appendString("popular").appendString("").appendInt(1)
                .appendString("popular").appendString("Popular").appendInt(1).appendBoolean(false).appendInt(0).appendInt(1)
                .appendInt(1).appendString("Room").appendInt(2).appendString("Alice").appendInt(0).appendInt(3).appendInt(20)
                .appendString("Test").appendInt(1).appendInt(4).appendInt(5).appendInt(6).appendInt(1).appendString("tag")
                .appendInt(31).appendString("pic").appendInt(7).appendString("group").appendString("badge")
                .appendString("ad").appendString("details").appendInt(8);
        HPacket navigatorOutput = new HPacket(1);
        new HNavigatorSearchResult(navigatorInput).appendToPacket(navigatorOutput);
        System.out.println("navigator=" + HexFormat.of().formatHex(navigatorOutput.toBytes()));
        for (int mask = 0; mask < 64; mask++) for (int variant = 0; variant < 4; variant++) {
            HPacket input = new HPacket(1);
            input.appendInt(1).appendString("Room").appendInt(2).appendString("Alice").appendInt(0).appendInt(3).appendInt(20)
                .appendString("Test").appendInt(1).appendInt(4).appendInt(5).appendInt(6).appendInt(2).appendString("tag1").appendString("tag2")
                .appendInt(mask | 64);
            if ((mask & 1) != 0) input.appendString("pic");
            if ((mask & 2) != 0) input.appendInt((variant & 1) != 0 ? -1 : 7).appendString("group").appendString("badge");
            if ((mask & 4) != 0) input.appendString("ad").appendString("details").appendInt((variant & 2) != 0 ? -1 : 8);
            HNavigatorRoom room = new HNavigatorRoom(input);
            HPacket output = new HPacket(1); room.appendToPacket(output);
            System.out.println("navigator_room_input_" + mask + "_" + variant + "=" + HexFormat.of().formatHex(input.toBytes()));
            System.out.println("navigator_room_output_" + mask + "_" + variant + "=" + HexFormat.of().formatHex(output.toBytes()));
        }
        HPacket negativeBlocks = new HPacket(1); negativeBlocks.appendString("search").appendString("filter").appendInt(-1);
        HNavigatorSearchResult emptyBlocks = new HNavigatorSearchResult(negativeBlocks);
        HPacket normalizedBlocks = new HPacket(1); emptyBlocks.appendToPacket(normalizedBlocks);
        System.out.println("navigator_negative_blocks=" + HexFormat.of().formatHex(negativeBlocks.toBytes()));
        System.out.println("navigator_negative_blocks_normalized=" + HexFormat.of().formatHex(normalizedBlocks.toBytes()));
        HPacket negativeRooms = new HPacket(1); negativeRooms.appendString("search").appendString("filter").appendInt(1)
            .appendString("code").appendString("block").appendInt(1).appendBoolean(false).appendInt(0).appendInt(-1);
        HNavigatorSearchResult emptyRooms = new HNavigatorSearchResult(negativeRooms);
        HPacket normalizedRooms = new HPacket(1); emptyRooms.appendToPacket(normalizedRooms);
        System.out.println("navigator_negative_rooms=" + HexFormat.of().formatHex(negativeRooms.toBytes()));
        System.out.println("navigator_negative_rooms_normalized=" + HexFormat.of().formatHex(normalizedRooms.toBytes()));
        HPacket negativeTags = new HPacket(1);
        negativeTags.appendInt(1).appendString("Room").appendInt(2).appendString("Alice").appendInt(0).appendInt(3).appendInt(20)
            .appendString("Test").appendInt(1).appendInt(4).appendInt(5).appendInt(6).appendInt(-1);
        try { new HNavigatorRoom(negativeTags); throw new AssertionError("expected negative tag count rejection"); }
        catch (NegativeArraySizeException expected) { }
        System.out.println("navigator_negative_tags=" + HexFormat.of().formatHex(negativeTags.toBytes()));

        HPacket comments = new HPacket(1);
        comments.appendInt(1).appendInt(2).appendInt(0).appendInt(1).appendInt(3).appendInt(4).appendInt(5)
                .appendString("Alice").appendString("figure").appendInt(6).appendString("hello")
                .appendByte((byte) 10).appendInt(7).appendString("moderator").appendInt(8).appendInt(9);
        HCommentOverview parsedComments = new HCommentOverview(comments);
        if (parsedComments.getComments().get(0).getState() != HThreadState.HIDDEN_BY_ADMIN) throw new AssertionError("comment state");
        System.out.println("comments=" + HexFormat.of().formatHex(comments.toBytes()));

        HPacket threads = new HPacket(1);
        threads.appendInt(42).appendInt(3).appendInt(5);
        int[] states = {0, 10, 20, 42, 255};
        for (int i = 0; i < states.length; i++) {
            threads.appendInt(100 + i).appendInt(200 + i).appendString("Author" + i).appendString("Sujet é" + i)
                .appendBoolean(i % 2 == 0).appendBoolean(i % 2 != 0).appendInt(-i).appendInt(i + 3)
                .appendInt(i + 4).appendInt(i + 5).appendInt(i + 6).appendString("Last" + i)
                .appendInt(i + 7).appendByte((byte)states[i]).appendInt(i + 8).appendString("Admin" + i).appendInt(i + 9);
        }
        HThreadOverview threadOverview = new HThreadOverview(threads);
        HPacket normalizedThreads = new HPacket(1);
        normalizedThreads.appendInt(threadOverview.getGuildId()).appendInt(threadOverview.getStartIndex()).appendInt(threadOverview.getThreads().size());
        for (HThread t : threadOverview.getThreads()) {
            normalizedThreads.appendInt(t.getThreadId()).appendInt(t.getAuthorId()).appendString(t.getAuthorName()).appendString(t.getSubject())
                .appendBoolean(t.isPinned()).appendBoolean(t.isLocked()).appendInt(t.getPassedTime()).appendInt(t.getAmmountComments())
                .appendInt(t.getUnreadComments()).appendInt(t.getLastCommentIndexInForum()).appendInt(t.getLastCommentAuthorId())
                .appendString(t.getLastCommentAuthorName()).appendInt(t.getLastCommentPassedTime()).appendByte((byte)t.getState().state)
                .appendInt(t.getAdminId()).appendString(t.getAdminName()).appendInt(t.getUnknownThreadId());
        }
        if (threadOverview.getThreads().size() != 5 || threadOverview.getThreads().get(3).getState() != HThreadState.OPEN) throw new AssertionError("forum thread state");
        System.out.println("forum_threads=" + HexFormat.of().formatHex(threads.toBytes()));
        System.out.println("forum_threads_normalized=" + HexFormat.of().formatHex(normalizedThreads.toBytes()));
        HPacket negativeThreads = new HPacket(1); negativeThreads.appendInt(42).appendInt(3).appendInt(-1);
        if (!new HThreadOverview(negativeThreads).getThreads().isEmpty()) throw new AssertionError("negative thread count");
        System.out.println("forum_threads_negative=" + HexFormat.of().formatHex(negativeThreads.toBytes()));
        HPacket negativeForums = new HPacket(1); negativeForums.appendInt(0).appendInt(5).appendInt(3).appendInt(-1);
        if (!new HForumOverview(negativeForums).getForums().isEmpty()) throw new AssertionError("negative forum count");
        System.out.println("forum_overview_negative=" + HexFormat.of().formatHex(negativeForums.toBytes()));
        HPacket negativeComments = new HPacket(1); negativeComments.appendInt(1).appendInt(2).appendInt(3).appendInt(-1);
        if (!new HCommentOverview(negativeComments).getComments().isEmpty()) throw new AssertionError("negative comment count");
        System.out.println("forum_comments_negative=" + HexFormat.of().formatHex(negativeComments.toBytes()));
        for (int mode : new int[]{0, 1, 2, 99}) {
            HPacket forumList = new HPacket(1);
            forumList.appendInt(mode).appendInt(100).appendInt(5).appendInt(3);
            for (int i = 0; i < 3; i++) {
                forumList.appendInt(20 + i).appendString("Guild" + i).appendString("Description é" + i).appendString("Badge" + i)
                    .appendInt(-i).appendInt(i + 1).appendInt(i + 2).appendInt(i + 3).appendInt(i + 4)
                    .appendInt(i + 5).appendString("User" + i).appendInt(i + 6);
            }
            HForumOverview overview = new HForumOverview(forumList);
            HPacket normalized = new HPacket(1);
            normalized.appendInt(overview.getViewMode().getVal()).appendInt(overview.getSize()).appendInt(overview.getStartIndex()).appendInt(overview.getForums().size());
            for (HForum f : overview.getForums()) {
                normalized.appendInt(f.getGuildId()).appendString(f.getGuildName()).appendString(f.getGuildDescription()).appendString(f.getGuildBadge())
                    .appendInt(f.getUnknown1()).appendInt(f.getRating()).appendInt(f.getAmountComments()).appendInt(f.getUnreadComments())
                    .appendInt(f.getLastCommentIndexInForum()).appendInt(f.getLastCommentUserId()).appendString(f.getLastCommentUserName()).appendInt(f.getLastCommentPassedTime());
            }
            if (overview.getForums().size() != 3 || (mode == 99 && overview.getViewMode().getVal() != 2)) throw new AssertionError("forum overview");
            System.out.println("forum_overview_" + mode + "=" + HexFormat.of().formatHex(forumList.toBytes()));
            System.out.println("forum_overview_normalized_" + mode + "=" + HexFormat.of().formatHex(normalized.toBytes()));
        }

        for (int which = 0; which < 2; which++) {
            for (int where = 0; where < 2; where++) {
                HPacket input = new HPacket(1);
                if (where == 0) input.appendInt(-1); else input.appendInt(0).appendInt(-1);
                try {
                    if (which == 0) HFloorItem.parse(input); else HWallItem.parse(input);
                    throw new AssertionError("negative furniture count accepted");
                } catch (IllegalArgumentException | NegativeArraySizeException expected) { }
                HPacket summary = new HPacket(1); summary.appendInt(input.getReadIndex());
                System.out.println("furniture_count_input_" + which + "_" + where + "=" + HexFormat.of().formatHex(input.toBytes()));
                System.out.println("furniture_count_cursor_" + which + "_" + where + "=" + HexFormat.of().formatHex(summary.toBytes()));
            }
        }
        String[] wallIds = {"0", "-1", "+42", "0x7fffffff", "-0x80000000", "#a", "077", "08", "2147483648", "0x-1", "", " 1"};
        for (int i = 0; i < wallIds.length; i++) {
            HPacket input = new HPacket(1); input.appendString(wallIds[i]).appendInt(456).appendString(":w=1,2 l=3,4 r").appendString("state").appendInt(-1).appendInt(2).appendInt(42);
            System.out.println("wall_id_input_" + i + "=" + HexFormat.of().formatHex(input.toBytes()));
            try {
                HWallItem wallCase = new HWallItem(input); HPacket output = new HPacket(1); wallCase.appendToPacket(output);
                System.out.println("wall_id_output_" + i + "=" + HexFormat.of().formatHex(output.toBytes()));
            } catch (NumberFormatException expected) {
                // Invalid ID is expected to fail.
            }
        }
        for (int direction : new int[]{-1, 0, 1, 2, 3, 4, 5, 6, 7, 8}) {
            HPacket input = new HPacket(1); input.appendInt(77).appendInt(5).appendInt(3).appendInt(4).appendInt(direction).appendString("3.5").appendString("1").appendInt(0);
            new LegacyStuffData(0, 0, "3").appendToPacket(input);
            input.appendInt(-1).appendInt(2).appendInt(42);
            System.out.println("floor_direction_input_" + direction + "=" + HexFormat.of().formatHex(input.toBytes()));
            try {
                HFloorItem floorCase = new HFloorItem(input); HPacket output = new HPacket(1); floorCase.appendToPacket(output);
                System.out.println("floor_direction_output_" + direction + "=" + HexFormat.of().formatHex(output.toBytes()));
            } catch (ArrayIndexOutOfBoundsException expected) {
                // Invalid direction is expected to fail.
            }
        }
        HPacket entities = new HPacket(1);
        entities.appendInt(4);
        for (int i = 0; i < 4; i++) {
            entities.appendInt(i).appendString("name").appendString("motto").appendString("figure")
                    .appendInt(i).appendInt(1).appendInt(2).appendString("3.5").appendInt(5).appendInt(i + 1);
            if (i == 0) entities.appendString("M").appendInt(1).appendInt(2).appendString("g").appendString("x").appendInt(3).appendBoolean(true).appendInt(4);
            if (i == 1) entities.appendInt(1).appendInt(2).appendString("Alice").appendInt(3).appendBoolean(true).appendBoolean(false).appendBoolean(true).appendBoolean(false).appendBoolean(true).appendBoolean(false).appendInt(4).appendString("sit");
            if (i == 3) entities.appendString("F").appendInt(8).appendString("Bob").appendInt(2).appendShort((short) 0).appendShort((short) -1);
        }
        HEntity[] parsedEntities = HEntity.parse(entities);
        if (parsedEntities.length != 4 || parsedEntities[0].getEntityType() != HEntityType.HABBO || parsedEntities[3].getEntityType() != HEntityType.BOT || parsedEntities[1].getTile().getZ() != 3.5) throw new AssertionError("entities");
        System.out.println("entities=" + HexFormat.of().formatHex(entities.toBytes()));
        for (int type : new int[]{0, -1, 5, Integer.MAX_VALUE}) {
            HPacket input = new HPacket(1); appendEntityBase(input, type);
            HEntity entity = new HEntity(input);
            if (entity.getEntityType() != null || input.getReadIndex() != input.getBytesLength()) throw new AssertionError("unknown entity type");
            try { entity.appendToPacket(new HPacket(1)); throw new AssertionError("expected unknown type failure"); }
            catch (NullPointerException expected) { }
            System.out.println("entity_unknown_" + type + "=" + HexFormat.of().formatHex(input.toBytes()));
        }
        String[] genders = {"M", "m", "F", "f", "U", "u", "?", ""};
        for (int i = 0; i < genders.length; i++) {
            HPacket input = new HPacket(1); appendEntityBase(input, 1);
            input.appendString(genders[i]).appendInt(1).appendInt(2).appendString("group").appendString("extra").appendInt(3).appendBoolean(true).appendInt(4);
            HEntity entity = new HEntity(input);
            if (i < 6) {
                HPacket output = new HPacket(1); entity.appendToPacket(output);
                System.out.println("entity_gender_output_" + i + "=" + HexFormat.of().formatHex(output.toBytes()));
                if (i == 0) System.out.println("entity_habbo_construct=" + HexFormat.of().formatHex(HEntity.constructPacket(new HEntity[]{entity}, 1).toBytes()));
            } else {
                if (entity.getGender() != null) throw new AssertionError("unknown gender");
                try { entity.appendToPacket(new HPacket(1)); throw new AssertionError("expected unknown gender failure"); }
                catch (NullPointerException expected) { }
            }
            System.out.println("entity_gender_input_" + i + "=" + HexFormat.of().formatHex(input.toBytes()));
        }
        for (int flags = 0; flags < 64; flags++) {
            HPacket input = new HPacket(1); appendEntityBase(input, 2);
            input.appendInt(-2).appendInt(17).appendString("owner é").appendInt(-4);
            for (int bit = 0; bit < 6; bit++) input.appendBoolean((flags & (1 << bit)) != 0);
            input.appendInt(99).appendString("posture");
            HEntity pet = new HEntity(input); HPacket output = new HPacket(1); pet.appendToPacket(output);
            System.out.println("entity_pet_input_" + flags + "=" + HexFormat.of().formatHex(input.toBytes()));
            System.out.println("entity_pet_output_" + flags + "=" + HexFormat.of().formatHex(output.toBytes()));
        }
        for (int count : new int[]{0, 1, 4}) {
            HPacket input = new HPacket(1); appendEntityBase(input, 4);
            input.appendString("raw gender").appendInt(-8).appendString("owner é").appendInt(count);
            short[] values = {0, -1, Short.MIN_VALUE, Short.MAX_VALUE};
            for (int i = 0; i < count; i++) input.appendShort(values[i]);
            HEntity botCase = new HEntity(input); HPacket output = new HPacket(1); botCase.appendToPacket(output);
            System.out.println("entity_bot_input_" + count + "=" + HexFormat.of().formatHex(input.toBytes()));
            System.out.println("entity_bot_output_" + count + "=" + HexFormat.of().formatHex(output.toBytes()));
        }
        HPacket botNegative = new HPacket(1); appendEntityBase(botNegative, 4);
        botNegative.appendString("b").appendInt(8).appendString("owner").appendInt(-1);
        HEntity bot = new HEntity(botNegative); HPacket botNormalized = new HPacket(1); bot.appendToPacket(botNormalized);
        System.out.println("entity_bot_negative_skills=" + HexFormat.of().formatHex(botNegative.toBytes()));
        System.out.println("entity_bot_negative_skills_normalized=" + HexFormat.of().formatHex(botNormalized.toBytes()));
        HPacket negativeEntities = new HPacket(1); negativeEntities.appendInt(-1);
        try { HEntity.parse(negativeEntities); throw new AssertionError("expected negative entity count failure"); }
        catch (NegativeArraySizeException expected) { }
        System.out.println("entity_negative_count=" + HexFormat.of().formatHex(negativeEntities.toBytes()));
        HPacket negativeEntityUpdates = new HPacket(1); negativeEntityUpdates.appendInt(-1);
        try { HEntityUpdate.parse(negativeEntityUpdates); throw new AssertionError("expected negative update count failure"); }
        catch (NegativeArraySizeException expected) { }
        System.out.println("entity_update_negative_count=" + HexFormat.of().formatHex(negativeEntityUpdates.toBytes()));
        for (int direction : new int[]{-1, 8}) {
            HPacket input = new HPacket(1); input.appendInt(1).appendInt(7).appendInt(1).appendInt(2).appendString("3.5").appendInt(direction).appendInt(0).appendString("");
            try { HEntityUpdate.parse(input); throw new AssertionError("expected invalid direction failure"); }
            catch (ArrayIndexOutOfBoundsException expected) { }
            System.out.println("entity_update_direction_" + direction + "=" + HexFormat.of().formatHex(input.toBytes()));
        }
    }
}
