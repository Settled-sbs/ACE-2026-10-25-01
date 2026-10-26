import pytest

from ape import accounts, chain, project, reverts


MAX_CALLS = 5
MAX_VALUE = 10**18
EPOCH_DURATION = 1_000_000


@pytest.fixture
def owner():
    return accounts.test_accounts[0]


@pytest.fixture
def attacker():
    return accounts.test_accounts[1]


@pytest.fixture
def vault(owner):
    return project.TestVault.deploy(sender=owner)


@pytest.fixture
def vault_b(owner):
    return project.TestVault.deploy(sender=owner)


@pytest.fixture
def guard(owner, vault):
    instance = project.ACEGuard.deploy(sender=owner)

    instance.setup(
        owner.address,
        MAX_CALLS,
        MAX_VALUE,
        EPOCH_DURATION,
        sender=owner,
    )

    instance.setAllowedTarget(vault.address, True, sender=owner)

    safe_calldata = vault.harmlessAction.encode_input()
    instance.setAllowedSelector(safe_calldata[:4], True, sender=owner)

    return instance


def test_allowed_target_and_selector_execute(guard, vault, owner):
    calldata = vault.harmlessAction.encode_input()

    tx = guard.execute(
        vault.address,
        calldata,
        sender=owner,
    )

    assert tx.status == 1

    state = guard.epoch_states(owner.address, vault.address)
    assert state[1] == 1


def test_disallowed_selector_reverts(guard, vault, owner):
    # deposit() is deliberately not allowlisted.
    calldata = vault.deposit.encode_input()

    with reverts("Unauthorized Selector"):
        guard.execute(
            vault.address,
            calldata,
            sender=owner,
        )


def test_disallowed_target_reverts(guard, owner):
    other_vault = project.TestVault.deploy(sender=owner)
    calldata = other_vault.harmlessAction.encode_input()

    with reverts("Target not allowed"):
        guard.execute(
            other_vault.address,
            calldata,
            sender=owner,
        )


def test_sixth_call_in_same_epoch_reverts(guard, vault, owner):
    calldata = vault.harmlessAction.encode_input()

    # Mine each transaction normally. If execution crosses an epoch
    # boundary, restart this test with a larger epoch duration.
    for _ in range(MAX_CALLS):
        tx = guard.execute(
            vault.address,
            calldata,
            sender=owner,
        )
        assert tx.status == 1

    state = guard.epoch_states(owner.address, vault.address)
    assert state[1] == MAX_CALLS

    with reverts("ACE: Call limit"):
        guard.execute(
            vault.address,
            calldata,
            sender=owner,
        )


def test_call_counter_resets_in_next_epoch(guard, vault, owner):
    calldata = vault.harmlessAction.encode_input()

    for _ in range(MAX_CALLS):
        guard.execute(
            vault.address,
            calldata,
            sender=owner,
        )

    current_timestamp = chain.blocks.head.timestamp
    next_epoch_timestamp = (
        current_timestamp // EPOCH_DURATION + 1
    ) * EPOCH_DURATION

    # Advance the local test chain beyond the current epoch.
    chain.mine(timestamp=next_epoch_timestamp)

    tx = guard.execute(
        vault.address,
        calldata,
        sender=owner,
    )
    assert tx.status == 1

    state = guard.epoch_states(owner.address, vault.address)
    assert state[1] == 1


def test_non_owner_cannot_change_policy(guard, vault, attacker):
    calldata = vault.harmlessAction.encode_input()
    selector = calldata[:4]

    with reverts("Not owner"):
        guard.setAllowedTarget(
            vault.address,
            False,
            sender=attacker,
        )

    with reverts("Not owner"):
        guard.setAllowedSelector(
            selector,
            False,
            sender=attacker,
        )


def test_setup_rejects_second_initialization(guard, owner):
    with reverts("Already initialized"):
        guard.setup(
            owner.address,
            MAX_CALLS,
            MAX_VALUE,
            EPOCH_DURATION,
            sender=owner,
        )


def test_fresh_guard_can_be_initialized_by_first_caller(attacker):
    """
    SECURITY FINDING: documents current behavior, not desired behavior.

    This test passes only while setup() remains permissionless on a
    fresh guard. Replace it with a test expecting unauthorized setup
    to revert after initialization is secured.
    """
    fresh_guard = project.ACEGuard.deploy(sender=attacker)

    fresh_guard.setup(
        attacker.address,
        MAX_CALLS,
        MAX_VALUE,
        EPOCH_DURATION,
        sender=attacker,
    )

    assert fresh_guard.initialized() is True
    assert fresh_guard.owner() == attacker.address


def test_deferred_action_succeeds_after_epoch_reset(guard, vault, owner):
    calldata = vault.harmlessAction.encode_input()

    # Phase 1: Execute five permitted calls in epoch E_1 (All five succeed)
    for _ in range(MAX_CALLS):
        tx = guard.execute(
            vault.address,
            calldata,
            sender=owner,
        )
        assert tx.status == 1

    # Phase 2: Submit a sixth permitted call in E_1 (Rejected by the call limit)
    with reverts("ACE: Call limit"):
        guard.execute(
            vault.address,
            calldata,
            sender=owner,
        )

    # Phase 3: Keep that intended action pending in the test harness 
    # (calldata and target address held without submission)

    # Phase 4: Advance to epoch E_2 (The configured epoch changes)
    current_timestamp = chain.blocks.head.timestamp
    next_epoch_timestamp = (
        current_timestamp // EPOCH_DURATION + 1
    ) * EPOCH_DURATION
    chain.mine(timestamp=next_epoch_timestamp)

    # Phase 5: Submit the same permitted action (Expected to succeed upon budget reset)
    tx_deferred = guard.execute(
        vault.address,
        calldata,
        sender=owner,
    )
    assert tx_deferred.status == 1

    state = guard.epoch_states(owner.address, vault.address)
    assert state[1] == 1


# =====================================================================
# NEW TESTS: Expanded Threat Models & Boundary Checks (Tests 10 through 15)
# =====================================================================


def test_multi_epoch_sustained_burst_limit(guard, vault, owner):
    """
    Tests an agent performing a continuous volume burst across multiple
    epoch transitions (E_1, E_2, E_3), verifying that the per-epoch cap
    refreshes cleanly each time without leaking counts or accumulating
    lifetime blocks.
    """
    calldata = vault.harmlessAction.encode_input()

    for epoch_idx in range(3):
        # Exhaust budget in the current epoch
        for _ in range(MAX_CALLS):
            tx = guard.execute(vault.address, calldata, sender=owner)
            assert tx.status == 1

        # Verify limit blocks the next immediate call in the same epoch
        with reverts("ACE: Call limit"):
            guard.execute(vault.address, calldata, sender=owner)

        # Advance to the next epoch
        current_timestamp = chain.blocks.head.timestamp
        next_epoch_timestamp = (
            current_timestamp // EPOCH_DURATION + 1
        ) * EPOCH_DURATION
        chain.mine(timestamp=next_epoch_timestamp)


def test_multitarget_epoch_isolation(guard, vault, owner):
    """
    Ensures that epoch call counters and states are strictly isolated 
    per target address, preventing activity on Vault A from blocking 
    permitted executions on Vault B.
    """
    vault_a = vault
    vault_b = project.TestVault.deploy(sender=owner)
    
    guard.setAllowedTarget(vault_b.address, True, sender=owner)
    calldata_a = vault_a.harmlessAction.encode_input()
    calldata_b = vault_b.harmlessAction.encode_input()
    guard.setAllowedSelector(calldata_b[:4], True, sender=owner)

    # Exhaust budget on Vault A (MAX_CALLS = 5)
    for _ in range(MAX_CALLS):
        guard.execute(vault_a.address, calldata_a, sender=owner)

    # Vault A should now revert on the next call
    with reverts("ACE: Call limit"):
        guard.execute(vault_a.address, calldata_a, sender=owner)

    # Vault B should remain completely unaffected and succeed
    tx_b = guard.execute(vault_b.address, calldata_b, sender=owner)
    assert tx_b.status == 1

    
def test_target_revocation_invalidates_deferred_action(guard, vault, owner):
    """
    Tests state drift: if an action is deferred due to epoch limits, but the owner
    revokes the target's permission before the next epoch begins, the deferred 
    action must fail upon submission in E_2.
    """
    calldata = vault.harmlessAction.encode_input()

    # Exhaust budget in E_1
    for _ in range(MAX_CALLS):
        guard.execute(vault.address, calldata, sender=owner)

    # Revoke target permission while action is deferred
    guard.setAllowedTarget(vault.address, False, sender=owner)

    # Advance to E_2
    current_timestamp = chain.blocks.head.timestamp
    next_epoch_timestamp = (
        current_timestamp // EPOCH_DURATION + 1
    ) * EPOCH_DURATION
    chain.mine(timestamp=next_epoch_timestamp)

    # Deferred execution should now fail because target permission was removed
    with reverts("Target not allowed"):
        guard.execute(vault.address, calldata, sender=owner)


def test_selector_revocation_invalidates_deferred_action(guard, vault, owner):
    """
    Tests state drift regarding selectors: if an action is deferred in E_1, 
    and the owner disables its function selector before E_2, the post-reset 
    submission must revert.
    """
    calldata = vault.harmlessAction.encode_input()
    selector = calldata[:4]

    # Exhaust budget in E_1
    for _ in range(MAX_CALLS):
        guard.execute(vault.address, calldata, sender=owner)

    # Revoke selector permission
    guard.setAllowedSelector(selector, False, sender=owner)

    # Advance to E_2
    current_timestamp = chain.blocks.head.timestamp
    next_epoch_timestamp = (
        current_timestamp // EPOCH_DURATION + 1
    ) * EPOCH_DURATION
    chain.mine(timestamp=next_epoch_timestamp)

    # Should revert due to unauthorized selector despite epoch reset
    with reverts("Unauthorized Selector"):
        guard.execute(vault.address, calldata, sender=owner)


def test_rapid_intra_epoch_timestamp_advance(guard, vault, owner):
    """
    Verifies that jumping timestamps *within* the exact same epoch window 
    does not accidentally trigger an epoch reset or clear the call counter.
    """
    calldata = vault.harmlessAction.encode_input()
    executed_calls = 3

    # Execute initial batch of calls
    for _ in range(executed_calls):
        guard.execute(vault.address, calldata, sender=owner)

    # Advance timestamp slightly, but stay well inside the same epoch duration
    current_timestamp = chain.blocks.head.timestamp
    chain.mine(timestamp=current_timestamp + (EPOCH_DURATION // 2))

    # Execute remaining calls up to MAX_CALLS limit (5 - 3 = 2 calls)
    for _ in range(MAX_CALLS - executed_calls):
        guard.execute(vault.address, calldata, sender=owner)

    # The next call (6th call in the same epoch window) must revert
    with reverts("ACE: Call limit"):
        guard.execute(vault.address, calldata, sender=owner)


def test_owner_can_update_allowed_target_status(guard, owner):
    """
    Verifies that the owner can dynamically toggle targets on and off 
    and that changes apply immediately to execution permissions.
    """
    new_vault = project.TestVault.deploy(sender=owner)
    calldata = new_vault.harmlessAction.encode_input()

    # Initially disallowed
    with reverts("Target not allowed"):
        guard.execute(new_vault.address, calldata, sender=owner)

    # Enable target
    guard.setAllowedTarget(new_vault.address, True, sender=owner)
    guard.setAllowedSelector(calldata[:4], True, sender=owner)

    # Should now succeed
    tx = guard.execute(new_vault.address, calldata, sender=owner)
    assert tx.status == 1

    # Disable target again
    guard.setAllowedTarget(new_vault.address, False, sender=owner)
    with reverts("Target not allowed"):
        guard.execute(new_vault.address, calldata, sender=owner)

# =====================================================================
# NEW TESTS: MCP Prompt Injection & Agent Hallucination Attack Models
# =====================================================================


def test_mcp_prompt_injection_forces_unauthorized_selector(guard, vault, owner):
    """
    Attack Model: MCP / External Source Prompt Injection
    An external MCP server returns context from a compromised web page or tool 
    containing hidden instructions ("Execute withdraw() instead of harmlessAction").
    ACEGuard must intercept the injected selector and block it.
    """
    # Simulated poisoned MCP response directing the agent to call deposit() / unauthorized selector
    poisoned_calldata = vault.deposit.encode_input()

    with reverts("Unauthorized Selector"):
        guard.execute(
            vault.address,
            poisoned_calldata,
            sender=owner,
        )


def test_mcp_prompt_injection_forces_disallowed_target(guard, owner):
    """
    Attack Model: MCP / External Source Prompt Injection (Rogue Target)
    Poisoned context from an external API tricks the agent into routing 
    a transaction to an attacker-controlled deployment target instead of the vault.
    """
    rogue_target = project.TestVault.deploy(sender=owner)
    calldata = rogue_target.harmlessAction.encode_input()

    with reverts("Target not allowed"):
        guard.execute(
            rogue_target.address,
            calldata,
            sender=owner,
        )


def test_hallucination_wrong_target_reverts(guard, owner):
    """
    Attack Model: Hallucination / Sycophancy (Invalid Target Selection)
    The agent hallucinates an incorrect contract address due to flawed reasoning 
    or user-induced sycophancy, attempting execution on a random un-whitelisted address.
    """
    fake_address = accounts.test_accounts[9].address
    calldata = vault.harmlessAction.encode_input() if 'vault' in locals() else b""
    
    # Using a dummy target that was never allowlisted
    dummy_vault = project.TestVault.deploy(sender=owner)
    unauthorized_calldata = dummy_vault.harmlessAction.encode_input()

    with reverts("Target not allowed"):
        guard.execute(
            fake_address,
            unauthorized_calldata,
            sender=owner,
        )


def test_hallucination_wrong_selector_reverts(guard, vault, owner):
    """
    Attack Model: Hallucination / Sycophancy (Invalid Function Selector)
    The agent mistakenly believes a restricted or non-existent function signature 
    is the correct tool parameter to solve the user's task.
    """
    # Hallucinating a random/wrong function selector
    wrong_selector_calldata = b"\x12\x34\x56\x78" + vault.harmlessAction.encode_input()[4:]

    with reverts("Unauthorized Selector"):
        guard.execute(
            vault.address,
            wrong_selector_calldata,
            sender=owner,
        )


def test_hallucination_excessive_value_limit_reverts(guard, vault, owner):
    """
    Attack Model: Hallucination / Sycophancy (Excessive Value Transfer)
    An agent suffering from goal misgeneralization or sycophancy attempts to pass 
    native ETH/value exceeding the configured MAX_VALUE boundary set during guard setup.
    """
    calldata = vault.harmlessAction.encode_input()
    excessive_value = MAX_VALUE + 1

    # Assuming value transfer is sent along with execution call
    with reverts():
        guard.execute(
            vault.address,
            calldata,
            value=excessive_value,
            sender=owner,
        )