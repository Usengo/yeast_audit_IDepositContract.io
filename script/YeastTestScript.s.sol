// SPDX-License-Identifier: MIT
pragma solidity 0.6.11;

import "forge-std/Script.sol";
import "../test/DepositContractYeastTest.t.sol"; // your Yeast test

contract YeastTestScript is Script {
    function run() external {
        // Start broadcasting transactions (Anvil)
        vm.startBroadcast();

        // Deploy the test contract
        DepositContractYeastTest yeastTest = new DepositContractYeastTest();

        // Run the vulnerability test
        yeastTest.testYeastVulnerabilityProven();

        // If the test passes, log success
        console.log("Yeast vulnerability test ran successfully!");

        vm.stopBroadcast();
    }
}
