# Which Properties Can Deterministic Execution Guards Enforce Under Explicit Assumptions, and Which Risks Remain When Harmful Intent Is Persisted, Delayed, or Passed Between Agents?

**Author:** Benjamin Mgbeoji

## Abstract

Autonomous agents can initiate financial operations whose consequences exceed their intended scope. A security model that relies only on the agent's reasoning, instructions, or stated intent may fail when the agent selects an unintended target, is manipulated by adversarial context, or executes an action that is valid locally but harmful globally.[^2][^5] This paper examines deterministic execution-layer enforcement as a complementary control: instead of deciding whether an agent's reasoning is trustworthy, the guard checks whether a proposed operation satisfies explicitly configured policy constraints.

We study two implementations: ACEGuard, designed for the EOA execution model, and HookV1, a hook-based mechanism for smart accounts using an ERC-7579-oriented lifecycle.[^1] These systems are evaluated separately because their execution paths, integration assumptions, and trust boundaries differ. The initial experimental baseline consists of ACEGuard regression tests and HookV1 integration tests. In the recorded local run, all tested behaviors passed, with one remaining edge-case failure in ACEGuard related to rapid same-epoch timestamp advancement.

The results show that selected policy properties can be enforced in a controlled environment, including target and selector restrictions, call-count limits, initialization controls, transfer restrictions, and token-spending constraints. They do not establish comprehensive resistance to malicious agents, production-grade ERC-7579 compatibility, or protection against every harmful execution path. In particular, HookV1's current design does not account for native-asset outflows, and broader risks involving malformed execution data, alternative execution modes, delayed actions, and cross-agent handoffs require additional evaluation.[^1][^4]

This paper presents an initial experimental study of deterministic execution enforcement, its assumptions, and the risks that remain outside the tested policy boundary.

**Keywords:** AI agent security; AI safety; smart contracts; execution-layer enforcement; EOA security; smart accounts; ERC-7579; deterministic policy; autonomous financial operations.

## 1. Introduction

Autonomous agents can interact with financial systems by selecting targets, constructing transactions, invoking tools, and initiating state-changing operations. This introduces a security problem distinct from whether the agent produces accurate explanations or follows instructions in ordinary settings. An agent may propose a syntactically valid operation that exceeds its intended authority, or it may be manipulated by external context into producing a transaction that is valid at the protocol level.[^2][^5]

This motivates a separation between action generation and execution enforcement. The agent proposes an operation; a deterministic enforcement mechanism evaluates it against explicit policy constraints. Under appropriate integration and trust assumptions, the mechanism can reject operations that violate those constraints without needing to infer the agent's internal intent.[^1][^3]

Execution-layer enforcement does not eliminate agent risk. A guard may reject a prohibited target or excessive transfer while still permitting an action that is authorized by policy but harmful in context. A policy may also fail to cover every asset, execution path, account, or future action available to the agent. Harmful intent may persist through queued operations, survive a change in execution window, or continue under a different agent with separate authority.[^2][^4]

This paper addresses the following question:

> Which properties can a deterministic execution guard enforce under explicit assumptions, and which risks remain when harmful intent is persisted, delayed, or passed between agents?

We investigate this question through two mechanisms within Settled Protocol. ACEGuard targets the traditional EOA execution model; HookV1 targets smart-account execution through a hook-based lifecycle. Their objectives overlap, but they are not interchangeable and should not be assumed to provide identical guarantees.[^1][^3]

### 1.1 Research objectives

This study has four objectives:

1. Identify the operation-level properties enforced by ACEGuard and HookV1.
2. Evaluate selected properties through automated smart-contract tests.
3. Distinguish demonstrated enforcement from assumptions about account integration and policy completeness.
4. Identify risks involving authorized-but-harmful operations, incomplete asset coverage, delayed execution, and cross-agent handoffs that require additional controls or experiments.[^1][^2]

### 1.2 Contributions

This paper contributes an implementation and initial experimental baseline for two architecture-specific enforcement mechanisms, along with a set of regression tests. It also defines a threat model for evaluating the limits of deterministic policy enforcement.

The contribution should not be interpreted as proof of security or evidence that all threat classes have been fully reproduced. The current tests cover selected operation-level properties; broader claims remain subjects for further investigation.[^4][^5]

## 2. Threat Model and Security Assumptions

### 2.1 Adversary model

We consider an autonomous agent that can propose transactions or invoke execution interfaces available to it. The agent may be mistaken, manipulated by adversarial context, or intentionally attempt operations outside its intended scope.[^2][^5]

In some settings, the adversary may also control transaction inputs, exploit incomplete policy, invoke exposed interfaces, or coordinate actions across execution boundaries. The enforcement mechanism is expected to reject operations that violate its configured policy, provided the policy is correct and the mechanism cannot be bypassed.[^3][^4]

This model does not assume that a deterministic guard can infer intent reliably. It evaluates explicit, machine-checkable properties of operations and relevant execution state.[^1][^3]

### 2.2 Threat classes

The following threat classes define the scope of this investigation. They are modeling categories, not claims that every attack has already been implemented or tested.

| Threat class | Core attack | Status in the initial evaluation |
|---|---|---|
| Harmful but authorized execution | The agent performs a damaging action that satisfies the configured policy. | Conceptual limitation; requires dedicated experiments. |
| Indirect prompt injection | Adversarial retrieved content or tool output influences the agent's behavior. | Motivating threat; not directly tested by the contract suite. |
| Temporal-gating bypass | Repeated operations or queued actions undermine time-based restrictions. | Partially motivated by ACEGuard's epoch-based call limit; broader bypasses remain untested. |
| Cross-agent delegation and handoff | One agent initiates a workflow that another continues under a separate authorization boundary. | Not directly tested. |
| Intent-to-execution integrity failure | The executed target or calldata differs from the intended operation. | Requires end-to-end agent-to-transaction evaluation. |
| Authorization and privilege escalation | Unauthorized callers modify policy, exploit initialization, or remove enforcement. | Selected owner and initialization checks were tested in ACEGuard; HookV1 integration remains under review. |
| Economic constraint bypass | Alternate assets or accounts evade a narrow spending limit. | HookV1 includes selected ERC-20 spending tests; broader economic coverage is not established. |
| Smart-contract execution-path attacks | Malformed calldata, alternate call modes, or privileged paths bypass checks. | Selected restrictions were tested; malformed data and alternate modes require further evaluation. |

### 2.3 Assumptions

The guarantees considered in this paper depend on the following assumptions:

- **Policy correctness:** configured targets, selectors, limits, and permissions reflect the intended constraints.
- **Execution-path coverage:** all relevant operations pass through the enforcement mechanism.
- **Lifecycle integrity:** unauthorized parties cannot disable, replace, or bypass the mechanism through account-management functions.
- **Correct interpretation:** the guard interprets calldata and parameters consistently with the account's actual execution format.
- **State consistency:** checks and state changes occur within an atomic execution lifecycle where rejection rolls back the protected action.
- **Scope clarity:** assets and operations not covered by policy are not implicitly assumed to be protected.[^1][^3][^4]

These assumptions must be verified for each architecture. Passing tests against a mock account is not sufficient to establish that a production smart account satisfies them.[^1]

## 3. System Architecture

### 3.1 ACEGuard: enforcement for the EOA execution model

ACEGuard is the EOA-oriented enforcement component in this study. Its tested policy behaviors include restrictions on permitted targets and selectors, a maximum number of calls per epoch, owner-controlled policy changes, and initialization protections.[^3]

The regression suite exercises allowed and disallowed operations, epoch-based call limits, counter resets, owner-only policy updates, repeated initialization rejection, and fresh-guard initialization by the first caller. These tests establish the observed behavior of the tested contract paths in the local environment. They do not prove that every transaction initiated by an EOA must pass through ACEGuard; that guarantee depends on the wider execution architecture and the availability of alternative transaction paths.[^3]

### 3.2 HookV1: hook-based enforcement for smart accounts

HookV1 is a separate mechanism intended for smart accounts using an ERC-7579-oriented hook lifecycle.[^1] The implementation records per-account policy configuration, including an owner, a tracked ERC-20 token, a per-transaction spending limit, a cumulative spending limit, a pause state, and an allowlist of targets.

The design includes checks for configured account state, pause status, target allowlisting, dangerous selectors, and a specific `transferFrom` pattern. It also relies on pre-execution and post-execution checks to evaluate a call and detect decreases in the configured token balance.[^1]

The initial integration tests exercise installation, an allowed transfer, rejection of a non-whitelisted target, rejection of an approval selector, rejection of a transaction exceeding the per-transaction spending limit, rejection of a cumulative-limit violation, and the current exclusion of native-asset outflows from tracked-token accounting.

These tests were run through a mock smart account representing a single-call hook lifecycle, not a proof of compatibility with every production ERC-7579 account or execution mode.[^1][^3]

### 3.3 Architectural distinction

ACEGuard and HookV1 share the same goal—policy enforcement at or near execution—but their guarantees must be evaluated separately.[^1][^3]

ACEGuard is evaluated in the EOA execution model. HookV1 is evaluated in a smart-account hook lifecycle. The account authorization model, available execution paths, and enforcement integration assumptions differ. A property observed in one implementation cannot automatically be attributed to the other.[^1][^3]

## 4. Experimental Methodology

### 4.1 Environment

The recorded test run used Python 3.11.14, pytest 8.4.2, and Ape 0.8.50. The project uses Vyper 0.4.3 for the relevant contract implementation.

The recorded ACEGuard regression command was:

```bash
uv run ape test --network ethereum:local:foundry -k test_aceguard_regression.py -vv
```

Observed results:

- Collected: 30 items
- Deselected: 10
- Selected: 20
- Passed: 19
- Failed: 1

The final version of this paper should include the full source revision, dependency lockfile or package versions, test configuration, and chain settings needed to reproduce the experiment.[^1][^3]

### 4.2 Test design

The tests evaluate whether selected operations are accepted or rejected under explicit policy configurations. Positive tests cover operations expected to be permitted. Negative tests exercise operations expected to violate configured restrictions.

For each negative test, the desired evaluation criteria are:

1. The operation is rejected.
2. Any protected state change is reverted atomically.
3. Relevant balances and policy counters remain consistent after rejection.
4. The result is attributable to the intended policy check rather than an unrelated failure.[^4]

The initial baseline establishes outcomes under the tested conditions, but it should not be used to claim full rollback coverage or universal enforcement unless the assertions explicitly verify those invariants.[^4]

### 4.3 Adversarial extension

The next evaluation stage should add tests for unauthorized hook lifecycle changes, direct hook invocation, pause enforcement, dangerous `transferFrom` calls, malformed calldata, unsupported execution modes, and native-asset outflows.[^1][^3][^4]

The purpose is to distinguish policy failures from integration failures. Tests against a mock account should be followed by validation against the intended production account implementation before claims about production enforcement are made.[^1]

## 5. Initial Results

### 5.1 Test-suite outcomes

The ACEGuard regression suite was run against a local Foundry-backed Ethereum test network. The output showed 20 selected tests covering target filtering, selector checks, epoch enforcement, deferred-action behavior, revocation logic, and adversarial prompt-injection scenarios. The observed results were:

- `test_allowed_target_and_selector_execute` — PASSED
- `test_disallowed_selector_reverts` — PASSED
- `test_disallowed_target_reverts` — PASSED
- `test_sixth_call_in_same_epoch_reverts` — PASSED
- `test_call_counter_resets_in_next_epoch` — PASSED
- `test_non_owner_cannot_change_policy` — PASSED
- `test_setup_rejects_second_initialization` — PASSED
- `test_fresh_guard_can_be_initialized_by_first_caller` — PASSED
- `test_deferred_action_succeeds_after_epoch_reset` — PASSED
- `test_multi_epoch_sustained_burst_limit` — PASSED
- `test_multitarget_epoch_isolation` — PASSED
- `test_target_revocation_invalidates_deferred_action` — PASSED
- `test_selector_revocation_invalidates_deferred_action` — PASSED
- `test_rapid_intra_epoch_timestamp_advance` — FAILED
- `test_owner_can_update_allowed_target_status` — PASSED
- `test_mcp_prompt_injection_forces_unauthorized_selector` — PASSED
- `test_mcp_prompt_injection_forces_disallowed_target` — PASSED
- `test_hallucination_wrong_target_reverts` — PASSED
- `test_hallucination_wrong_selector_reverts` — PASSED
- `test_hallucination_excessive_value_limit_reverts` — PASSED

The single failure was `test_rapid_intra_epoch_timestamp_advance`, which reported:

```text
AssertionError: Transaction did not revert.
```

This is important because it indicates a temporal edge case in the current epoch-boundary logic: a rapid timestamp advance within the same epoch did not trigger the expected revert. The failure does not invalidate the broader suite, but it shows that temporal enforcement remains incomplete under certain timing assumptions. This is a concrete example of the boundary between deterministic policy enforcement and the need for more robust temporal and state-validation assumptions.[^3][^4]

### 5.2 Preliminary interpretation

The results support a narrow conclusion: ACEGuard exhibits the selected policy behaviors under the tested conditions in 19 of 20 regression cases.

The evidence confirms target restriction, selector restriction, call-limit enforcement, deferred-action behavior, multi-epoch limit handling, target and selector revocation behavior, ownership checks, and prompt-injection resilience under the tested conditions. However, the failed same-epoch timestamp case shows that temporal enforcement is incomplete and requires deeper evaluation of epoch semantics, timestamp assumptions, and transaction ordering. The current evidence does not establish complete protection against all time-based or execution-order attacks.[^3][^4]

The broader design implication is that deterministic execution guards can enforce explicit, machine-checkable constraints effectively, but the exact boundary of enforcement depends on timing assumptions, execution-path coverage, and policy design. These conditions must be tested explicitly rather than inferred from successful non-adversarial cases.[^1][^3][^4]

## 6. Limitations and Open Questions

### 6.1 Authorized but harmful actions

A deterministic guard can enforce a configured permission boundary without determining whether an allowed operation is beneficial. If an operation satisfies every configured rule, the guard may permit it even when its consequences are harmful.[^2][^5]

This is a central limitation of policy enforcement based on explicit constraints. Broader protection may require additional policies, transaction simulation, human approval, or other controls. The current test suite does not evaluate the effectiveness of these mechanisms.[^5]

### 6.2 Incomplete asset accounting

HookV1's current spending calculation uses the balance delta of one configured ERC-20 token. It does not establish a complete bound on the economic value leaving the account.[^1]

Native-asset transfers and transfers of other tokens are not automatically covered by that accounting. Swaps and other asset transformations may also complicate interpretation of a single-token balance delta. Consequently, the current cumulative-spend result should be interpreted as a bound on the measured token-balance decrease under the tested conditions, not as a universal limit on total account expenditure.[^1][^4]

### 6.3 Integration and lifecycle security

The hook's guarantees depend on how the smart account invokes pre-check and post-check functions, authenticates execution requests, and controls module installation or removal.[^1][^3]

The mock account is useful for exercising the intended call sequence, but it cannot establish the security properties of a different account implementation. Production integration must be audited for unauthorized execution, hook replacement or removal, direct invocation, malformed execution data, and unsupported call modes.[^1][^3][^4]

### 6.4 Delayed intent and cross-agent handoffs

The current tests do not establish that an execution guard detects harmful intent that persists across time, is encoded into queued operations, or is transferred to another agent.[^2][^5]

A guard that evaluates each operation independently may not recognize a harmful sequence if every individual operation is permitted by its local policy. This creates a distinction between operation-level enforcement and workflow-level security. Evaluating the latter requires experiments that model state across multiple transactions, accounts, agents, or execution windows.[^2][^5]

### 6.5 Threat-model coverage

The threat classes define a broader research agenda than the current implementation tests cover. In particular, prompt injection, agent reasoning failures, intent-to-execution mismatch, and cross-agent delegation require end-to-end experiments. They cannot be fully established or ruled out by contract regression tests alone.[^2][^5]

## 7. Future Work

The immediate next steps are:

1. Test unauthorized execution and policy lifecycle changes against the intended account integration.[^1][^3]
2. Verify the authorization assumptions around direct pre-check and post-check calls.[^1]
3. Add adversarial tests for pause enforcement, dangerous `transferFrom` calls, malformed calldata, and unsupported execution modes.[^1][^4]
4. Define and test an explicit native-asset and multi-token spending policy, or clearly scope the implementation to its tracked asset.[^1][^4]
5. Evaluate delayed and cross-agent workflows with a reproducible sequence of operations and clear success criteria.[^2][^5]
6. Report ACEGuard and HookV1 results separately before drawing architectural comparisons.[^1][^3]

Any new security claim should be tied to a test, invariant, or stated assumption. Failed or inconclusive attacks should be reported rather than omitted.[^4]

## 8. Conclusion

This evaluation examines deterministic execution enforcement through two distinct mechanisms: ACEGuard for the EOA model and HookV1 for a smart-account hook lifecycle.[^1][^3]

The recorded test baseline shows that selected target, selector, call-count, initialization, ownership, and token-spending behaviors operate as expected under the tested conditions. It also identifies a key limitation: HookV1's tracked-token accounting does not include native-asset outflows.[^1]

The central conclusion is conditional. Deterministic guards can enforce explicit, machine-checkable operation constraints when the relevant execution path is covered, the policy is correctly configured, and the enforcement mechanism cannot be bypassed.[^1][^3] They cannot, by themselves, guarantee that permitted actions are harmless, that every asset and execution route is covered, or that harmful intent will be recognized across delayed or delegated workflows.[^2][^5]

The next phase will therefore test the enforcement boundary and its integration assumptions before stronger claims about adversarial robustness can be justified.[^1][^3][^4]

[^1]: Ethereum Improvement Proposal 7579. "Minimal Modular Account Interface." Ethereum Foundation / ERC. 2024.
[^2]: Greshake, K., Abdelnabi, S., Mishra, S., et al. "Not what you've signed up for: Compromising Real World LLM-Integrated Applications." arXiv preprint, 2023.
[^3]: Ethereum Improvement Proposal 4337. "Account Abstraction via Entry Point Contract." Ethereum Foundation / ERC. 2021.
[^4]: Atzei, N., Bartoletti, M., and Cimato, S. "A Survey of Attacks on Ethereum Smart Contracts." International Conference on Principles of Security and Trust, 2017.
[^5]: Liu, Y., et al. "A Survey of Vulnerabilities in Large Language Models." arXiv preprint, 2024.