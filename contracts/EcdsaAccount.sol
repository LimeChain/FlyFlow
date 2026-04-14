// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.34;

import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

/// @title EcdsaAccount
/// @author pqc-4337-laim
/// @notice Baseline ERC-4337 v0.7 account. Inherits eth-infinitism's SimpleAccount
///         unchanged per DD-10 so gas measurements reflect the reference bytecode.
///         Intentionally contains no body beyond the constructor forward.
contract EcdsaAccount is SimpleAccount {
    constructor(IEntryPoint anEntryPoint) SimpleAccount(anEntryPoint) {}
}
