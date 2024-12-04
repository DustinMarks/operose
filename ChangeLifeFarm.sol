// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./interfaces/IUniswapV2Pair.sol";

contract ChangeLifeFarm is Initializable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
  struct PurchaseAuth {
    bytes signature;
    bytes32 nonce;
    uint deadline;
    uint8 id;
    address wallet;
  }

  struct Harvester {
    uint price;
    uint duration;
    uint tokensPerSecond;
    uint count;
    uint tokens;
  }

  struct OrderAuth {
    bytes signature;
    bytes32 nonce;
    uint deadline;
    uint id;
    uint stable;
    uint tokens;
    address wallet;
  }

  uint public setupFee;
  ERC20Upgradeable public token;
  ERC20Upgradeable public stableToken;
  address public authorizedSigner;
  address public authorizedWithdraw;
  mapping (bytes32 => bool) public nonceMap;
  mapping (address => uint) public setupFeeMap;
  mapping (uint8 => Harvester) public harvesterMap;
  mapping (address => uint[]) public harvesterExpireMap;
  mapping (address => uint8[]) public harvesterIdMap;
  mapping (address => uint) public harvestMap;
  mapping (address => uint) public harvestedMap;
  IUniswapV2Pair public pair;
  address public salesVault;

  error AlreadyPaid();
  error SoldOut();
  error TransferFailedStable();
  error TransferFailedTokens();
  error DeadlineExpired();
  error NonceUsed();
  error InvalidSignature();
  error InvalidSignatureLength();
  error InvalidWallet();

  event SetupFeePaid(address indexed buyer, uint amount, uint timestamp);
  event HarvesterPurchased(address indexed buyer, uint8 id, uint price, uint tokens, bytes32 nonce, uint timestamp);
  event TokensHarvested(address indexed account, uint amount, uint timestamp);
  event Withdraw(address indexed account, uint amount, bytes32 nonce, uint timestamp);
  event HarvesterUpdated(uint8 id, uint price, uint duration, uint tokensPerSecond, uint count);
  event HarvesterCountUpdated(uint8 id, uint count);
  event HarvesterPriceUpdated(uint8 id, uint price, uint tokens);
  event ShopPurchased(address indexed buyer, uint id, uint stable, uint tokens, bytes32 nonce, uint timestamp);

  function initialize(address _token, address _stable, address _authorizedSigner, address _authorizedWithdraw, uint _setupFee) public initializer {
    __Ownable_init(msg.sender);
    __ReentrancyGuard_init();
    
    token = ERC20Upgradeable(_token);
    stableToken = ERC20Upgradeable(_stable);
    authorizedSigner = _authorizedSigner;
    authorizedWithdraw = _authorizedWithdraw;
    setupFee = _setupFee;
  }

  function setupFeePaid(address account) external view returns (uint amount) { 
    amount = setupFeeMap[account];
  }

  function harvesterInfo(uint8 id) external view returns (Harvester memory) { 
    return harvesterMap[id];
  }

  function harvestInfo(address account) external view returns (uint[] memory) {
    uint[] memory info = new uint[](harvesterExpireMap[account].length * 2 + 2);
    info[0] = harvestMap[account];
    info[1] = harvestedMap[account];
    for (uint i = 0; i < harvesterIdMap[account].length; i++) {
      info[i * 2 + 2] = harvesterIdMap[account][i];
      info[i * 2 + 3] = harvesterExpireMap[account][i];
    }
    return info;
  }

  function chargeSetupFee() external nonReentrant {
    if (setupFeeMap[msg.sender] > 0) revert AlreadyPaid();
    if (!stableToken.transferFrom(msg.sender, address(this), setupFee)) revert TransferFailedStable();
    setupFeeMap[msg.sender] = setupFee;
    emit SetupFeePaid(msg.sender, setupFee, block.timestamp);
  }

  function buyHarvester(PurchaseAuth calldata auth) external nonReentrant {
    bytes32 messageHash = keccak256(abi.encodePacked(auth.id, auth.nonce, auth.deadline, auth.wallet));
    if (!_verifySignature(messageHash, auth.signature)) revert InvalidSignature();
    Harvester storage harvester = harvesterMap[auth.id];
    if (harvester.count == 0) revert SoldOut();
    if (msg.sender != auth.wallet) revert InvalidWallet();
    if (block.timestamp > auth.deadline) revert DeadlineExpired();
    if (nonceMap[auth.nonce]) revert NonceUsed();

    uint stable = (harvester.price * harvester.tokens) / 100e6;
    if (!stableToken.transferFrom(msg.sender, address(this), harvester.price - stable)) revert TransferFailedStable();
    uint tokens = stableToToken(stable);
    if (tokens > 0) {
      if (!token.transferFrom(msg.sender, address(this), tokens)) revert TransferFailedTokens();
    }

    if (salesVault != address(0)) {
      if (!stableToken.transfer(salesVault, harvester.price - stable)) revert TransferFailedStable();
    }

    _harvest(msg.sender);
    harvesterIdMap[msg.sender].push(auth.id);
    harvesterExpireMap[msg.sender].push(block.timestamp + harvester.duration);
    harvester.count--;

    nonceMap[auth.nonce] = true;
    emit HarvesterPurchased(msg.sender, auth.id, harvester.price - stable, tokens, auth.nonce, block.timestamp);
  }

  function harvest() public nonReentrant returns (uint amount) {
    return _harvest(msg.sender);
  }

  function _harvest(address account) private returns (uint amount) {
    uint lastHarvest = harvestMap[account];
    uint8[] memory ids = harvesterIdMap[account];
    uint[] memory expires = harvesterExpireMap[account];

    for (uint i = 0; i < ids.length; i++) {
      uint8 id = ids[i];
      uint expireTime = expires[i];
      uint tokensPerSecond = harvesterMap[id].tokensPerSecond;

      if (expireTime > block.timestamp) {
        amount += ((block.timestamp - lastHarvest) * tokensPerSecond);
      } else if (expireTime > lastHarvest) {
        amount += ((expireTime - lastHarvest) * tokensPerSecond);
      }
    }

    if (amount > 0) {
      if (!token.transfer(account, amount)) revert TransferFailedTokens();
      harvestedMap[account] += amount;
      emit TokensHarvested(account, amount, block.timestamp);
    }
    harvestMap[account] = block.timestamp;
  }

  function withdraw(address account, uint256 amount, bytes32 nonce, uint deadline) external nonReentrant {
    if (msg.sender != authorizedWithdraw) revert InvalidWallet();
    if (block.timestamp > deadline) revert DeadlineExpired();
    if (nonceMap[nonce]) revert NonceUsed();
    nonceMap[nonce] = true;
    if (!stableToken.transfer(account, amount)) revert TransferFailedStable();
    emit Withdraw(account, amount, nonce, block.timestamp);
  }

  function setSetupFee(uint value) external onlyOwner {
    setupFee = value;
  }

  function ownerBuyHarvester(address account, bytes32 nonce, uint8 id) external onlyOwner {
    if (nonceMap[nonce] == false) {
      _harvest(account);
      Harvester storage harvester = harvesterMap[id];
      harvesterIdMap[account].push(id);
      harvesterExpireMap[account].push(block.timestamp + harvester.duration);
      harvester.count--;
      nonceMap[nonce] = true;
    }
  }

  function setHarvester(uint8 id, uint price, uint tokens, uint duration, uint tokensPerSecond, uint count) external onlyOwner {
    Harvester storage harvester = harvesterMap[id];
    harvester.price = price;
    harvester.tokens = tokens;
    harvester.duration = duration;
    harvester.tokensPerSecond = tokensPerSecond;
    harvester.count = count;
    emit HarvesterUpdated(id, price, duration, tokensPerSecond, count);
  }

  function setHarvesterCount(uint8 id, uint256 amount) external onlyOwner {
    harvesterMap[id].count = amount;
    emit HarvesterCountUpdated(id, amount);
  }

  function setHarvesterPrice(uint8 id, uint256 price, uint tokens) external onlyOwner {
    harvesterMap[id].price = price;
    harvesterMap[id].tokens = tokens;
    emit HarvesterPriceUpdated(id, price, tokens);
  }

  function shopOrder(OrderAuth calldata auth) external nonReentrant {
    bytes32 messageHash = keccak256(abi.encodePacked(auth.id, auth.stable, auth.tokens, auth.nonce, auth.deadline, auth.wallet));
    if (!_verifySignature(messageHash, auth.signature)) revert InvalidSignature();
    if (msg.sender != auth.wallet) revert InvalidWallet();
    if (block.timestamp > auth.deadline) revert DeadlineExpired();
    if (nonceMap[auth.nonce]) revert NonceUsed();

    if (auth.stable > 0) {
      if (!stableToken.transferFrom(msg.sender, address(this), auth.stable)) revert TransferFailedStable();
    }

    if (auth.tokens > 0) {
      if (!token.transferFrom(msg.sender, address(this), auth.tokens)) revert TransferFailedTokens();
    }

    nonceMap[auth.nonce] = true;
    emit ShopPurchased(msg.sender, auth.id, auth.stable, auth.tokens, auth.nonce, block.timestamp);
  }

  function setAuthorizedSigner(address value) external onlyOwner {
    authorizedSigner = value;
  }

  function setAuthorizedWithdraw(address value) external onlyOwner {
    authorizedWithdraw = value;
  }

  function setSalesVault(address value) external onlyOwner {
    salesVault = value;
  }

  function setStableToken(address value) external onlyOwner {
    stableToken = ERC20Upgradeable(value);
  }

  function setPair(address value) external onlyOwner {
    pair = IUniswapV2Pair(value);
  }

  function pullStable(uint256 amount) external onlyOwner {
    stableToken.transfer(msg.sender, amount);
  }

  function pullTokens(uint256 amount) external onlyOwner {
    token.transfer(msg.sender, amount);
  }

  function addTokens(uint256 amount) external nonReentrant {
    token.transferFrom(msg.sender, address(this), amount);
  }

  function addStable(uint256 amount) external nonReentrant {
    stableToken.transferFrom(msg.sender, address(this), amount);
  }

  function stableToToken(uint256 stableAmount) public view returns (uint256 tokenAmount) {
    (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
    (uint112 reserveStable, uint112 reserveToken) = address(stableToken) == pair.token0() ? (reserve0, reserve1) : (reserve1, reserve0);
    tokenAmount = (stableAmount * reserveToken) / reserveStable;
  }

  function _verifySignature(bytes32 messageHash, bytes calldata signature) internal view returns (bool) {
    bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
    (bytes32 r, bytes32 s, uint8 v) = _splitSignature(signature);
    return ecrecover(ethSignedMessageHash, v, r, s) == authorizedSigner;
  }

  function _splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
    if (sig.length != 65) revert InvalidSignatureLength();
    assembly {
      r := mload(add(sig, 32))
      s := mload(add(sig, 64))
      v := byte(0, mload(add(sig, 96)))
    }
  }

  receive() external payable {
    revert("Ether not accepted");
  }

  fallback() external payable {
    revert("Ether not accepted");
  }
}
