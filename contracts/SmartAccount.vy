# @version ^0.4.3
"""
@title Production-Grade ERC-7579 Smart Account with Hook Firewall & ECDSA Validation
@notice Compliant with ERC-4337 and ERC-7579 with cryptographic verification and secure state management.
"""

interface IERC7579Hook:
    def isModuleType(moduleTypeId: uint256) -> bool: view
    def onInstall(data: Bytes[1024]): nonpayable
    def onUninstall(data: Bytes[1024]): nonpayable
    def preCheck(msgSender: address, msgValue: uint256, msgData: Bytes[8192]) -> Bytes[2048]: nonpayable
    def postCheck(hookData: Bytes[2048]): nonpayable

struct PackedUserOperation:
    sender: address
    nonce: uint256
    initCode: Bytes[1024]
    callData: Bytes[4096]
    accountGasLimits: bytes32
    preVerificationGas: uint256
    gasFees: bytes32
    paymasterAndData: Bytes[1024]
    signature: Bytes[1024]

MODULE_TYPE_HOOK: constant(uint256) = 4
SIG_VALIDATION_FAILED: constant(uint256) = 1

entryPoint: public(immutable(address))
owner: public(address)
isInitialized: public(bool)

installedModules: public(HashMap[uint256, HashMap[address, bool]])
activeHook: public(address)

event AccountInitialized:
    owner: indexed(address)
    entryPoint: indexed(address)

event ModuleInstalled:
    moduleTypeId: indexed(uint256)
    module: indexed(address)

event ModuleUninstalled:
    moduleTypeId: indexed(uint256)
    module: indexed(address)

event ExecutionSuccess:
    target: indexed(address)
    value: uint256

@deploy
def __init__(_entryPoint: address):
    assert _entryPoint != empty(address), "Invalid EntryPoint"
    entryPoint = _entryPoint
    # Lock implementation contract to prevent master copy hijacking
    self.owner = 0x000000000000000000000000000000000000dEaD
    self.isInitialized = True

@external
def initialize(_owner: address):
    """
    @notice Called by Factory immediately after deployment. Can only be called once.
    """
    assert not self.isInitialized, "Already initialized"
    assert _owner != empty(address), "Invalid owner"
    
    self.owner = _owner
    self.isInitialized = True
    log AccountInitialized(_owner, entryPoint)

@external
def validateUserOp(
    userOp: PackedUserOperation,
    userOpHash: bytes32,
    missingAccountFunds: uint256
) -> uint256:
    """
    @notice ERC-4337 entry point validation hook with cryptographic signature verification.
    """
    assert msg.sender == entryPoint, "Only EntryPoint can validate"

    # 1. Reimburse EntryPoint if required during validation
    if missingAccountFunds > 0:
        raw_call(entryPoint, b"", value=missingAccountFunds)

    # 2. Cryptographic Signature Verification (ECDSA via ecrecover)
    assert len(userOp.signature) == 65, "Invalid signature length"
    
    r: bytes32 = convert(slice(userOp.signature, 0, 32), bytes32)
    s: bytes32 = convert(slice(userOp.signature, 32, 32), bytes32)
    v: uint256 = convert(slice(userOp.signature, 64, 1), uint256)
    
    if v < 27:
        v += 27

    recoveredSigner: address = ecrecover(userOpHash, v, r, s)
    
    if recoveredSigner != self.owner or recoveredSigner == empty(address):
        return SIG_VALIDATION_FAILED

    # 0 indicates signature validation success (ERC-4337 standard)
    return 0

@external
def installModule(moduleTypeId: uint256, module: address, initData: Bytes[1024]):
    """
    @notice ERC-7579 compliant module installation. Supports Type 4 Hooks.
    """
    assert msg.sender == self.owner or msg.sender == self, "Unauthorized"
    assert not self.installedModules[moduleTypeId][module], "Module already installed"

    if moduleTypeId == MODULE_TYPE_HOOK:
        assert self.activeHook == empty(address), "Hook already installed"
        assert staticcall IERC7579Hook(module).isModuleType(MODULE_TYPE_HOOK), "Invalid Hook module type"
        self.activeHook = module

    self.installedModules[moduleTypeId][module] = True
    
    extcall IERC7579Hook(module).onInstall(initData)
    log ModuleInstalled(moduleTypeId, module)

@external
def uninstallModule(moduleTypeId: uint256, module: address, deInitData: Bytes[1024]):
    """
    @notice ERC-7579 compliant module uninstallation.
    """
    assert msg.sender == self.owner or msg.sender == self, "Unauthorized"
    assert self.installedModules[moduleTypeId][module], "Module not installed"

    if moduleTypeId == MODULE_TYPE_HOOK:
        assert self.activeHook == module, "Not active hook"
        self.activeHook = empty(address)

    self.installedModules[moduleTypeId][module] = False
    
    extcall IERC7579Hook(module).onUninstall(deInitData)
    log ModuleUninstalled(moduleTypeId, module)

@external
@payable
def execute(mode: bytes32, executionCalldata: Bytes[8192]) -> Bytes[4096]:
    """
    @notice ERC-7579 execution entrypoint. Intercepts transaction with HookV1 firewall.
    """
    assert msg.sender == entryPoint or msg.sender == self.owner, "Not authorized"

    hook: address = self.activeHook
    hookData: Bytes[2048] = b""

    # 1. FIREWALL PRE-CHECK INTERCEPTION
    # Pass executionCalldata directly since its type (Bytes[8192]) matches the interface
    if hook != empty(address):
        hookData = extcall IERC7579Hook(hook).preCheck(
            msg.sender, msg.value, executionCalldata
        )

    # 2. DECODE EXECUTION PAYLOAD (Single Call Format)
    assert len(executionCalldata) >= 52, "Malformed execution calldata"
    target: address = convert(slice(executionCalldata, 0, 20), address)
    value: uint256 = convert(slice(executionCalldata, 20, 32), uint256)
    
    callData: Bytes[8192] = b""
    if len(executionCalldata) > 52:
        callData = slice(executionCalldata, 52, len(executionCalldata) - 52)

    # 3. ATOMIC EXECUTION
    result: Bytes[4096] = raw_call(
        target,
        callData,
        max_outsize=4096,
        value=value
    )
    log ExecutionSuccess(target, value)

    # 4. FIREWALL POST-CHECK ENFORCEMENT
    if hook != empty(address):
        extcall IERC7579Hook(hook).postCheck(hookData)

    return result

@external
@payable
def __default__():
    pass