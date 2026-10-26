# pragma version ^0.4.0
"""
@title ACEGuard Delegate
@notice EIP-7702 delegate contract enforcing bitmasks, session keys, and velocity bounds.
"""

# =============================================================
# Events
# =============================================================
event Executed:
    caller: indexed(address)
    target: indexed(address)
    value: uint256
    success: bool

event SessionKeySet:
    key: indexed(address)
    expires: uint256

event SessionKeyRevoked:
    key: indexed(address)

# =============================================================
# Structs & Storage
# =============================================================
struct EpochState:
    last_epoch: uint256
    calls: uint256
    value_spent: uint256

initialized: public(bool)
owner: public(address)

session_keys: public(HashMap[address, uint256])
epoch_states: public(HashMap[address, HashMap[address, EpochState]])

max_calls_per_epoch: public(uint256)
max_value_per_epoch: public(uint256)
epoch_duration: public(uint256)

allowed_targets: public(HashMap[address, bool])
is_allowed_selector: public(HashMap[bytes4, bool])

# =============================================================
# Initialization
# =============================================================
@external
def setup(
    _owner: address,
    _max_calls: uint256,
    _max_value: uint256,
    _epoch_duration: uint256
):
    assert not self.initialized, "Already initialized"
    assert _epoch_duration > 0, "Invalid duration"
    assert _owner != empty(address), "Invalid owner"

    self.owner = _owner
    self.initialized = True
    
    self.max_calls_per_epoch = _max_calls
    self.max_value_per_epoch = _max_value
    self.epoch_duration = _epoch_duration

# =============================================================
# Owner Configuration
# =============================================================
@external
def setSessionKey(key: address, duration: uint256):
    assert msg.sender == self.owner or msg.sender == self, "Not owner"

    new_expiration: uint256 = block.timestamp + duration
    self.session_keys[key] = new_expiration
    log SessionKeySet(key, new_expiration)

@external
def revokeSessionKey(key: address):
    assert msg.sender == self.owner or msg.sender == self, "Not owner"
    self.session_keys[key] = 0
    log SessionKeyRevoked(key)

@external
def setAllowedSelector(selector: bytes4, allowed: bool):
    assert msg.sender == self.owner or msg.sender == self, "Not owner"
    self.is_allowed_selector[selector] = allowed

@external
def setAllowedTarget(target: address, allowed: bool):
    assert msg.sender == self.owner or msg.sender == self, "Not owner"
    self.allowed_targets[target] = allowed

@external
def reset():
    assert msg.sender == self.owner or msg.sender == self, "Not owner"

    self.initialized = False
    self.owner = empty(address)

    self.max_calls_per_epoch = 0
    self.max_value_per_epoch = 0
    self.epoch_duration = 0


# =============================================================
# Execution
# =============================================================
@external
@payable
def execute(
    target: address,
    calldata: Bytes[1024]
) -> Bytes[1024]:
    caller: address = msg.sender
    
    # 1. Authorization check: Owner and self bypass session expiration
    if caller != self.owner and caller != self:
        expiry: uint256 = self.session_keys[caller]
        assert expiry > 0 and block.timestamp <= expiry, "Session invalid or expired"

    # 2. Selector check
    assert len(calldata) >= 4, "Calldata too short"
    target_selector: bytes4 = convert(slice(calldata, 0, 4), bytes4)
    assert self.is_allowed_selector[target_selector], "Unauthorized Selector"

    # 3. Target check 
    assert self.allowed_targets[target], "Target not allowed"

    # 4. Epoch velocity limits
    current_epoch: uint256 = block.timestamp // self.epoch_duration
    state: EpochState = self.epoch_states[caller][target]

    if state.last_epoch != current_epoch:
        state.calls = 0
        state.value_spent = 0
        state.last_epoch = current_epoch

    assert state.calls < self.max_calls_per_epoch, "ACE: Call limit"
    assert state.value_spent + msg.value <= self.max_value_per_epoch, "ACE: Value limit"

    state.calls += 1
    state.value_spent += msg.value

    # Commit memory struct back to storage mapping
    self.epoch_states[caller][target] = state

    # 5. Raw execution call
    response: Bytes[1024] = raw_call(
        target,
        calldata,
        max_outsize=1024,
        value=msg.value,
        revert_on_failure=True
    )

    log Executed(caller, target, msg.value, True)
    return response

@external
@payable
def __default__():
    pass