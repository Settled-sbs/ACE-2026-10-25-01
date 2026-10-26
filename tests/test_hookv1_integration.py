import pytest
from eth_abi import encode
from ape import reverts, project, accounts
from ape_ethereum.proxies import ProxyInfo, ProxyType

@pytest.fixture
def owner():
    return accounts.test_accounts[0]

@pytest.fixture
def recipient():
    return accounts.test_accounts[1]

@pytest.fixture
def unauthorized_user():
    return accounts.test_accounts[2]

@pytest.fixture
def entrypoint():
    return accounts.test_accounts[4]


@pytest.fixture
def mock_token(owner):
    return project.MockUSDC.deploy(sender=owner)


@pytest.fixture
def hook(owner):
    return project.HookV1.deploy(sender=owner)


@pytest.fixture
def account_impl(entrypoint, owner):
    return project.SmartAccount.deploy(entrypoint.address, sender=owner)


@pytest.fixture
def factory(account_impl, owner):
    return project.AccountFactory.deploy(account_impl.address, sender=owner)

@pytest.fixture
def account(owner, factory, hook, mock_token, account_impl):
    salt = 123
    receipt = factory.createAccount(owner.address, salt, sender=owner)
    account_address = receipt.return_value

    account_contract = project.SmartAccount.at(
        account_address,
        proxy_info=ProxyInfo(
            type=ProxyType.Vyper,
            target=account_impl.address,
        ),
    )

    init_data = encode(
        ['address', 'address', 'uint256', 'uint256', 'address[4]'],
        [
            owner.address,
            mock_token.address,
            100,
            500,
            [mock_token.address, owner.address, "0x0000000000000000000000000000000000000000", "0x0000000000000000000000000000000000000000"]
        ]
    )
    account_contract.installModule(4, hook.address, init_data, sender=owner)
    return account_contract

def test_unauthorized_execution(account, mock_token, unauthorized_user):
    """Ensure non-owner/non-entrypoint callers cannot invoke execute on the smart account."""
    execution_calldata = encode(['address', 'uint256', 'bytes'], [mock_token.address, 0, b""])
    
    with reverts("Not authorized"):
        account.execute(
            b"\x00" * 32, # default single call mode
            execution_calldata,
            sender=unauthorized_user
        )


def test_unauthorized_module_uninstall(hook, account, unauthorized_user):
    """Ensure unauthorized users cannot uninstall security hook modules."""
    with reverts("Unauthorized"):
        account.uninstallModule(4, hook.address, b"", sender=unauthorized_user)


def test_unauthorized_pause_toggle(hook, account, unauthorized_user):
    """Ensure only the configured owner can toggle the emergency pause on HookV1."""
    with reverts("only owner can toggle pause"):
        hook.togglePause(account.address, sender=unauthorized_user)


def test_direct_precheck_uninstalled_sender(hook, unauthorized_user):
    """Directly calling preCheck from an account that has never installed the firewall must revert."""
    with reverts("firewall not installed"):
        hook.preCheck(
            unauthorized_user.address, 
            0, 
            b"\x00" * 120, 
            sender=unauthorized_user
        )


def test_postcheck_account_mismatch(hook, owner):
    """Ensure postCheck rejects payload mismatches where msg.sender does not match the encoded account."""
    fake_account = "0x0000000000000000000000000000000000001234"
    hook_data = encode(['address', 'uint256'], [fake_account, 100])
    
    with reverts("hookData/account mismatch"):
        hook.postCheck(hook_data, sender=owner)


def test_malformed_execution_calldata_too_short(account, owner):
    """Smart account execute() must revert if executionCalldata lacks minimum length for target and value (< 52 bytes)."""
    truncated_data = b"\x00" * 20  # Only 20 bytes
    
    with reverts("malformed execution calldata"):
        account.execute(
            b"\x00" * 32,
            truncated_data,
            sender=owner
        )


def test_hook_malformed_msgdata_decoding(account, owner):
    """HookV1 preCheck must revert with 'malformed execution calldata' when calldata length is >= 52 but < 120 bytes."""
    # 80 bytes passes SmartAccount execute() length check (>= 52) but fails HookV1 preCheck length check (< 120)
    semi_truncated_data = b"\x00" * 80
    
    with reverts("malformed execution calldata"):
        account.execute(
            b"\x00" * 32,
            semi_truncated_data,
            sender=owner
        )