import pytest
from eth_abi import encode
from ape import project, accounts, reverts


@pytest.fixture
def owner():
    return accounts[0]

@pytest.fixture
def recipient():
    return accounts[2]

@pytest.fixture
def unauthorized_user():
    return accounts[3]

@pytest.fixture
def entrypoint():
    return accounts[1]

@pytest.fixture
def mock_token(owner):
    return project.MockUSDC.deploy(sender=owner)

@pytest.fixture
def hook(owner):
    return project.HookV1.deploy(sender=owner)

@pytest.fixture
def account_impl(entrypoint):
    return project.SmartAccount.deploy(entrypoint.address, sender=accounts[0])

@pytest.fixture
def factory(account_impl):
    return project.AccountFactory.deploy(account_impl.address, sender=accounts[0])

@pytest.fixture
def account(owner, factory, hook, mock_token):
    salt = 123
    account_address = factory.createAccount(owner.address, salt, sender=owner)
    account_contract = project.SmartAccount.at(account_address)
    
    # Install HookV1 module
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
            b"\x00" * 32,
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