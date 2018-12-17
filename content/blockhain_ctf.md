Title: Blockchain CTF Lvl. 1-5
Date: 2018-12-17 10:01
Modified: 2018-12-17 10:01
Category: ctf
Tags: ctf, ethereum, solidity
Slug: blockchain_ctf15
Authors: F3real
Summary: How to solve Blockchain CTF lvl. 1-5

Blockchain CTF can be found on
[here](https://blockchain-ctf.securityinnovation.com/#/)

To play, we just need to install and configure Metamask addon. It will give us our own etherium address (don't forget to change network to `Ropsten Test Network`) and inject web3.js library into javascript context so we can access it trough our browser console. 

To get free test etherium, required to play go to [here](https://faucet.metamask.io/) or [here](https://faucet.ropsten.be/).

Other useful tools for doing this CTF:

* Explore network transactions [etherscan](https://etherscan.io/)
* Easy way to send eth or call contract functions [mycrypto](https://mycrypto.com/)

So let's start:

[TOC]

## Lvl 1 Donation

When we open challenge page, we are given contract address, contract ABI and solidity source code of target contract.

~~~solidity
contract Donation is CtfFramework{
    using SafeMath for uint256;
    uint256 public funds;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        funds = funds.add(msg.value);
    }
    
    function() external payable ctf{
        funds = funds.add(msg.value);
    }

    function withdrawDonationsFromTheSuckersWhoFellForIt() external ctf{
        msg.sender.transfer(funds);
        funds = 0;
    }
}
~~~

In this first contract we see that we just need to call `withdrawDonationsFromTheSuckersWhoFellForIt` since it has `external` modifier.  `external` modifier denotes that function can only be called from outside of contract.

Our solution:
~~~javascript
var abi = [...]
var tokenContractAddress = "contract_address"
var contract = web3.eth.contract(abi).at(tokenContractAddress)

//set default account to account 0
web3.eth.defaultAccount = web3.eth.accounts[0];
contract.withdrawDonationsFromTheSuckersWhoFellForIt((err,res)=>{console.log(err,res);});
~~~

## Lvl 2 Lock box

~~~solidity
pragma solidity 0.4.24;
import "../CtfFramework.sol";

contract Lockbox1 is CtfFramework{
    uint256 private pin;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        pin = now%10000;
    }
    
    function unlock(uint256 _pin) external ctf{
        require(pin == _pin, "Incorrect PIN");
        msg.sender.transfer(address(this).balance);
    }
}
~~~

Second, challenge is also pretty simple. Key is in usage of `now` (an alias for `block.timestamp`) which is `uint256` value in seconds since the unix epoch.

In metamask we can open our last transaction (that is transaction used to create this contract), check exact time, convert it to unix timestamp and just enter last 4 digits to win.

## Lvl 3 Piggy bank

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";
import "../../node_modules/openzeppelin-solidity/contracts/math/SafeMath.sol";

contract PiggyBank is CtfFramework{
    using SafeMath for uint256;
    uint256 public piggyBalance;
    string public name;
    address public owner;
    
    constructor(address _ctfLauncher, address _player, string _name) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        name=_name;
        owner=msg.sender;
        piggyBalance=piggyBalance.add(msg.value);
    }
    
    function() external payable ctf{
        piggyBalance=piggyBalance.add(msg.value);
    }
    
    modifier onlyOwner(){
        require(msg.sender == owner, "Unauthorized: Not Owner");
        _;
    }

    function withdraw(uint256 amount) internal{
        piggyBalance = piggyBalance.sub(amount);
        msg.sender.transfer(amount);
    }

    function collectFunds(uint256 amount) public onlyOwner ctf{
        require(amount<=piggyBalance, "Insufficient Funds in Contract");
        withdraw(amount);
    }   
}

contract CharliesPiggyBank is PiggyBank{   
    uint256 public withdrawlCount;
    
    constructor(address _ctfLauncher, address _player) public payable
        PiggyBank(_ctfLauncher, _player, "Charlie") 
    {
        withdrawlCount = 0;
    }
    
    function collectFunds(uint256 amount) public ctf{
        require(amount<=piggyBalance, "Insufficient Funds in Contract");
        withdrawlCount = withdrawlCount.add(1);
        withdraw(amount);
    }   
}
~~~

Description of challenge:
```
This contract belongs to Charlie with the address ********,
Charlie is the only person capable of withdrawing from this contract
Your wallet is ********, so you are not Charlie and you can not withdraw.
```
If we look at `collectFunds` in `PiggyBank` we see `onlyOwner` modifier which checks if `msg.sender == owner` (`msg.sender` is address from which request was sent).

But in `CharliesPiggyBank`, which inherits from `PiggyBank`, modifier is missing so we can just call it to win.

## Lvl 4 SI Token Sale

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";
// https://github.com/OpenZeppelin/openzeppelin-solidity/blob/v1.8.0/contracts/token/ERC20/StandardToken.sol
import "../StandardToken.sol";

contract SIToken is StandardToken {
    using SafeMath for uint256;

    string public name = "SIToken";
    string public symbol = "SIT";
    uint public decimals = 18;
    uint public INITIAL_SUPPLY = 1000 * (10 ** decimals);

    constructor() public{
        totalSupply_ = INITIAL_SUPPLY;
        balances[this] = INITIAL_SUPPLY;
    }
}

contract SITokenSale is SIToken, CtfFramework {
    uint256 public feeAmount;
    uint256 public etherCollection;
    address public developer;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        feeAmount = 10 szabo; 
        developer = msg.sender;
        purchaseTokens(msg.value);
    }

    function purchaseTokens(uint256 _value) internal{
        require(_value > 0, "Cannot Purchase Zero Tokens");
        require(_value < balances[this], "Not Enough Tokens Available");
        balances[msg.sender] += _value - feeAmount;
        balances[this] -= _value;
        balances[developer] += feeAmount; 
        etherCollection += msg.value;
    }

    function () payable external ctf{
        purchaseTokens(msg.value);
    }

    // Allow users to refund their tokens for half price ;-)
    function refundTokens(uint256 _value) external ctf{
        require(_value>0, "Cannot Refund Zero Tokens");
        transfer(this, _value);
        etherCollection -= _value/2;
        msg.sender.transfer(_value/2);
    }

    function withdrawEther() external ctf{
        require(msg.sender == developer, "Unauthorized: Not Developer");
        require(balances[this] == 0, "Only Allowed Once Sale is Complete");
        msg.sender.transfer(etherCollection);
    }
}
~~~

This challenge was far trickier then first three. Key is in `purchaseTokens` function, `balances[msg.sender] += _value - feeAmount;`.
Only check made is that value is not 0, so by sending very small value we can actually underflow our balance.
After setting up contract variable our solution is (just remember to double required amount of eth since it's divided by 2 before transfer):

~~~javascript
web3.eth.sendTransaction({from:web3.eth.defaultAccount ,to:tokenContractAddress, value: web3.toWei(0.000009)}, (err,res)=>{console.log(err,res);})
contract.refundTokens(web3.toWei(0.600018), function(err,ok) { console.log(err,ok) } )
~~~

## Lvl 5 Secure Bank

~~~solidity
pragma solidity 0.4.24;

import "../CtfFramework.sol";

contract SimpleBank is CtfFramework{
    mapping(address => uint256) public balances;

    constructor(address _ctfLauncher, address _player) public payable
        CtfFramework(_ctfLauncher, _player)
    {
        balances[msg.sender] = msg.value;
    }

    function deposit(address _user) public payable ctf{
        balances[_user] += msg.value;
    }

    function withdraw(address _user, uint256 _value) public ctf{
        require(_value<=balances[_user], "Insufficient Balance");
        balances[_user] -= _value;
        msg.sender.transfer(_value);
    }

    function () public payable ctf{
        deposit(msg.sender);
    }

}

contract MembersBank is SimpleBank{
    mapping(address => string) public members;

    constructor(address _ctfLauncher, address _player) public payable
        SimpleBank(_ctfLauncher, _player)
    {
    }

    function register(address _user, string _username) public ctf{
        members[_user] = _username;
    }

    modifier isMember(address _user){
        bytes memory username = bytes(members[_user]);
        require(username.length != 0, "Member Must First Register");
        _;
    }

    function deposit(address _user) public payable isMember(_user) ctf{
        super.deposit(_user);
    }

    function withdraw(address _user, uint256 _value) public isMember(_user) ctf{
        super.withdraw(_user, _value);
    }

}

contract SecureBank is MembersBank{
    constructor(address _ctfLauncher, address _player) public payable
        MembersBank(_ctfLauncher, _player)
    {
    }

    function deposit(address _user) public payable ctf{
        require(msg.sender == _user, "Unauthorized User");
        require(msg.value < 100 ether, "Exceeding Account Limits");
        require(msg.value >= 1 ether, "Does Not Satisfy Minimum Requirement");
        super.deposit(_user);
    }

    function withdraw(address _user, uint8 _value) public ctf{
        require(msg.sender == _user, "Unauthorized User");
        require(_value < 100, "Exceeding Account Limits");
        require(_value >= 1, "Does Not Satisfy Minimum Requirement");
        super.withdraw(_user, _value * 1 ether);
    }

    function register(address _user, string _username) public ctf{
        require(bytes(_username).length!=0, "Username Not Enough Characters");
        require(bytes(_username).length<=20, "Username Too Many Characters");
        super.register(_user, _username);
    }
}
~~~

This was really interesting challenge. Problem we have to solve is that call to function `withdraw` checks if `msg.sender == _user`.

First thing I wanted to check is mapping `balances` to get key under which 0.4 ETH where stored.

Easiest way is to use [etherscan](https://etherscan.io/) and find `Contact creator` address for this contract. We can see that creator is the key under funds are put by looking at constructor for `SimpleBank`.

Interestingly, there is no way to get keys from mapping itself in solidity.
To verify if key we have gotten is correct, we can use:

~~~javascript
contract.balances("0x2272071889eDCeACABce7dfec0b1E017c6Cad120",(err,res)=>{console.log(res.toNumber());})
~~~

Without `toNumber` results are hard to read, so don't forget to use it.

But this only works since in our case mapping is actually public. With a bit digging around it turns that we can read values even from private mappings:

~~~javascript
var slot = "0000000000000000000000000000000000000000000000000000000000000001"
var key =  "00000000000000000000000x2272071889eDCeACABce7dfec0b1E017c6Cad120"
var contractAddress = "**************"
web3.eth.getStorageAt(
  contractAddress,  // address of the contract to read from
  web3.sha3(key+slot, { encoding: 'hex' }),  // keccak256(k . p)
  function (err, result) {
    console.log(web3.toDecimal(result)); 
  }
);
~~~

Some notes:

* Slot depends on place of state variable we are trying to access. I expected slot to be 0 for balances but it turned out to be 1, probably due the way variables are ordered when they are inherited.
* both slot and key need to be expanded, like in example, to 64 characters

Looking carefully at source, we can see that function `withdraw` has different signature in `SecureBank` which means it is not overloading `withdraw` from `MembersBank`.
In `MembersBank` there is no address check in `withdraw` but we have two new problems. First we need to pass `isMember` modifier. This is done simply by registering any username with `0x2272071889eDCeACABce7dfec0b1E017c6Cad120` address. Second problem is how to call this function, `web3.js` is terrible at handling functions with same name and it will just call `withdraw` in `SecureBank` no matter which parameters we pass.

To get around this we need to make our own call payload and send it.
If we look at `etherscan` data of function call is something like:
```text
Function: register(address owner, string gravatarHash) ***
MethodID: 0x32434a2e
[0]:  0000000000000000000000002272071889edceacabce7dfec0b1e017c6cad120
[1]:  0000000000000000000000000000000000000000000000000000000000000040
[2]:  0000000000000000000000000000000000000000000000000000000000000005
[3]:  456f733932000000000000000000000000000000000000000000000000000000
```
First we have  function ID, this is just first 32 bytes of sha256 of function name and parameter types.
We can calculate it using web3.js:

~~~javascript
web3.sha3('withdraw(address,uint256)')
"0xf3fef3a3f44f9c277339b67d54f015748bd8d6b77a985b0ab6e71126b018c34a"
~~~
After ID, parameters come in order they are declared:
* we have address expanded to 64 bytes in line 0
* then in lines 1,2,3 we have string. String are passed a bit differently first, on line of parameter we have offset to actual data (0x40 = 64), then on line given by offset he have number of characters in string (5) and on line\[s\] after that we have actual hex encoded string.

In our case encoded data and call are:

```text
Function: withdraw(address addr, uint256 amount) ***

MethodID: 0xf3fef3a3
[0]:  0000000000000000000000002272071889edceacabce7dfec0b1e017c6cad120
[1]:  000000000000000000000000000000000000000000000000058d15e176280000
```

~~~javascript
var tx = {
    to : contractAddress,
    data : "0xf3fef3a30000000000000000000000002272071889edceacabce7dfec0b1e017c6cad120000000000000000000000000000000000000000000000000058d15e176280000"
}
web3.eth.sendTransaction(tx, (err,res)=>{console.log(err,res);});
~~~