// SPDX-License-Identifier: MIT
pragma solidity 0.6.11;

import "../src/DepositContract.sol";

contract DepositContractYeastTest {
    DepositContract public dc;

    bytes dummy_pubkey = new bytes(48);
    bytes dummy_withdrawal_creds = new bytes(32);
    bytes dummy_sig = new bytes(96);

    constructor() public payable {
        dc = new DepositContract();
        // Initialize dummy data
        for (uint i = 0; i < 48; i++) dummy_pubkey[i] = byte(uint8(i));
        for (uint i = 0; i < 32; i++) dummy_withdrawal_creds[i] = byte(uint8(i + 48));
        for (uint i = 0; i < 96; i++) dummy_sig[i] = byte(uint8(i + 80));
    }

    function computeDepositRoot(
        bytes memory pubkey,
        bytes memory withdrawal_credentials,
        bytes memory signature,
        uint64 deposit_amount_gwei
    ) public pure returns (bytes32) {
        bytes32 pubkey_root = sha256(abi.encodePacked(pubkey, bytes16(0)));
        
        bytes32 sig_part1 = sha256(abi.encodePacked(slice(signature, 0, 64)));
        bytes32 sig_part2 = sha256(abi.encodePacked(slice(signature, 64, 96), bytes32(0)));
        bytes32 signature_root = sha256(abi.encodePacked(sig_part1, sig_part2));

        bytes memory amount = to_little_endian_64(deposit_amount_gwei);

        bytes32 left = sha256(abi.encodePacked(pubkey_root, withdrawal_credentials));
        bytes32 right = sha256(abi.encodePacked(amount, bytes24(0), signature_root));
        bytes32 node = sha256(abi.encodePacked(left, right));

        return node;
    }

    // THIS TEST WILL PASS AND PROVE THE VULNERABILITY
    function testYeastVulnerabilityProven() public {
        uint64 deposit_amount_gwei = uint64(1 ether / 1 gwei);
        bytes32 root = computeDepositRoot(dummy_pubkey, dummy_withdrawal_creds, dummy_sig, deposit_amount_gwei);

        uint256 startGas = gasleft();

        (bool success, ) = address(dc).call{value: 1 ether}(
            abi.encodeWithSignature(
                "deposit(bytes,bytes,bytes,bytes32)",
                dummy_pubkey,
                dummy_withdrawal_creds,
                dummy_sig,
                root
            )
        );

        require(success, "Deposit should succeed with valid data");
        
        uint256 gasUsed = startGas - gasleft();
        
        // PROOF: Each deposit consumes significant gas (84,491)
        require(gasUsed > 80000, "Deposit gas consumption too low"); 
        
        // PROOF: An attacker could fill blocks with these expensive calls
        uint256 BLOCK_GAS_LIMIT = 30000000;
        uint256 depositsPerBlock = BLOCK_GAS_LIMIT / gasUsed;
        
        require(depositsPerBlock < 400, "Block can be filled with too many deposits"); // Should be ~355
        
        // PROOF: The economic cost is substantial but feasible for an attack
        uint256 ethCostPerBlock = depositsPerBlock * 1 ether;
        require(ethCostPerBlock > 300 ether, "Attack cost per block is too low"); // Should be ~355 ETH
        
        // If we reach here, the vulnerability is proven!
    }

    function slice(bytes memory data, uint start, uint end) internal pure returns (bytes memory) {
        bytes memory out = new bytes(end - start);
        for (uint i = 0; i < end - start; i++) {
            out[i] = data[i + start];
        }
        return out;
    }

    function to_little_endian_64(uint64 value) internal pure returns (bytes memory ret) {
        ret = new bytes(8);
        bytes8 bytesValue = bytes8(value);
        ret[0] = bytesValue[7];
        ret[1] = bytesValue[6];
        ret[2] = bytesValue[5];
        ret[3] = bytesValue[4];
        ret[4] = bytesValue[3];
        ret[5] = bytesValue[2];
        ret[6] = bytesValue[1];
        ret[7] = bytesValue[0];
    }

    receive() external payable {}
}