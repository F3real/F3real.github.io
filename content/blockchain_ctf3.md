Title: Blockchain CTF Lvl. 10-11
Date: 2018-12-22 10:01
Modified: 2018-12-22 10:01
Category: ctf
Tags: ctf, ethereum, solidity
Slug: blockchain_ctf1011
Authors: F3real
Summary: How to solve Blockchain CTF lvl. 10-11

In this post we will take a look at last two challenges 10 and 11.

So let's start:

[TOC]

## Lvl 10 Slot Machine

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";
import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

contract SlotMachine is CtfFramework{
    using SafeMath for uint256;
    uint256 public winner;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        winner = 5 ether;
    }
    
    function() external payable ctf{
        require(msg.value == 1 szabo, "Incorrect Transaction Value");
        if (address(this).balance >= winner){
            msg.sender.transfer(address(this).balance);
        }
    }
}
~~~

To win we need to make contract balance greater or equal 5 eth. But we see that, we can only send 1 `szabo` (0.000001 eth) at the time to contract. 

There are two ways to avoid activating fallback function:

1. miner block rewards
2. using `selfdestruct`
3. send ether to contract before it is created

Since we don't want to mine, we will go with approach two. Function `selfdestruct(address)` destroys contract and transfers all balance to specified address. It is a way of cleaning contracts from blockchain.

Our solution:
~~~solidity
function endIt() external {
    require(msg.sender == owner);
    selfdestruct(slotContractAddress);
}
~~~

## Lvl 11 Rainy Day Fund

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";

contract DebugAuthorizer{  
    bool public debugMode;

    constructor() public payable{
        if(address(this).balance == 1.337 ether){
            debugMode=true;
        }
    }
}

contract RainyDayFund is CtfFramework{
    address public developer;
    mapping(address=>bool) public fundManagerEnabled;
    DebugAuthorizer public debugAuthorizer;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        //debugAuthorizer = (new DebugAuthorizer).value(1.337 ether)(); // Debug mode only used during development
        debugAuthorizer = new DebugAuthorizer();
        developer = msg.sender;
        fundManagerEnabled[msg.sender] = true;
    }
    
    modifier isManager() {
        require(fundManagerEnabled[msg.sender] || debugAuthorizer.debugMode() || msg.sender == developer, "Unauthorized: Not a Fund Manager");
         _;
    }

    function () external payable ctf{
        // Anyone can add to the fund    
    }
    
    function addFundManager(address _newManager) external isManager ctf{
        fundManagerEnabled[_newManager] = true;
    }

    function removeFundManager(address _previousManager) external isManager ctf{
        fundManagerEnabled[_previousManager] = false;
    }

    function withdraw() external isManager ctf{
        msg.sender.transfer(address(this).balance);
    }
}
~~~

We see that there is modifier `isManager` blocking us to withdraw funds from contract. To bypass it we can either be contract creator or be in debug mode.

If we look at contract `DebugAuthorizer` it sets `debugMode` to true only if balance is 1.337 eth during creation. This means that we need to send eth to contract before it is created.

Contract addresses in ethereum are deterministic and can be calculated using following formula:
```keccak(RLP(sender address, nonce)))```

RLP stands for Recursive Length Prefix, a type of encoding used by ethereum. Good explanation can be found on [wiki](https://github.com/ethereum/wiki/wiki/RLP).

In solidity we can calculate address as follows:
```
function addressFrom(address _origin, uint _nonce) external pure returns (address) {
    return address(keccak256(byte(0xd6), byte(0x94), _origin, byte(_nonce)));
}
```
Let's explain these magic numbers.

1. Since we are RLP encoding array `[address, nonce]`, first number we have to provide is `0xd6` = `0xc0` (for lists of total length less then 55 bytes, as defined in standard) + `0x16` (length of list in our case)
2. `0x94` = `0x80` (constant for strings 0-55 bytes long) + `0x14` (length of address without prefix `0x`, 20 bytes)
3. nonce has no RLP prefix since we assume here that it will be smaller then `0x7f`, otherwise we would need to add it as well as modify first byte.

Since we now know how to calculate future address lets look at how we can get `nonce`. Nonce is number that is sequentially incremented after each transaction, starting from 0 in case of wallet addresses.

Contracts are a bit special, their `nonce` value starts at 1 (since EIP 161) and gets only incremented when contract creates another contract. To find current nonce we can use `etherscan` and count number of contracts creations (under `Internal Txns` tab) or we can get same number using javascript.

~~~javascript
web3.eth.getTransactionCount("0xed0d5160c642492b3b482e006f67679f5b6223a2", (err,res)=>{console.log(err,res);})
~~~

Looking at the source, we see that we need to calculate new address two times:

1. first find current nonce of `developer` contract and calculate address of new `RainyDayFund` contract that will be created.
2. since `RainyDayFund` contract will create new contract `DebugAuthorizer` in constructor, we need to calculate address of that contract as well (`nonce` will be 1 since it is first contract created from `RainyDayFund`)

After getting both addresses we need to send 1.337 eth to address we calculated for `DebugAuthorizer` contract and reset challenge from dashboard to redeploy `RainyDayFund`. If we did everythin correctly we can just call withdraw and win :D