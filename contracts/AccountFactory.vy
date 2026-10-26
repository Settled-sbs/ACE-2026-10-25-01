# @version ^0.4.3
"""
@title Production-Grade ERC-4337 Account Factory
@notice Deploys minimal proxy Smart Accounts deterministically with secure initialization.
"""

interface ISmartAccount:
    def initialize(_owner: address): nonpayable

accountImplementation: public(immutable(address))

event AccountCreated:
    account: indexed(address)
    owner: indexed(address)
    salt: uint256

@deploy
def __init__(_implementation: address):
    assert _implementation != empty(address), "Invalid implementation"
    accountImplementation = _implementation

@external
def createAccount(owner: address, salt: uint256) -> address:
    """
    @notice Deploys a new smart account deterministically.
    @dev CREATE2 handles collision safety; reverts if already deployed with the same salt.
    """
    assert owner != empty(address), "Invalid owner"

    # Bind salt with owner to isolate namespaces per owner
    combinedSalt: bytes32 = keccak256(concat(convert(owner, bytes32), convert(salt, bytes32)))
    
    deployedAccount: address = create_forwarder_to(
        accountImplementation,
        salt=combinedSalt
    )

    extcall ISmartAccount(deployedAccount).initialize(owner)
    log AccountCreated(deployedAccount, owner, salt)
    return deployedAccount