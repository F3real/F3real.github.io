Title: Ethernaut wargame Lvl. 19
Date: 2019-1-13 10:01
Modified: 2019-1-13 10:01
Category: ctf
Tags: ctf, ethereum, solidity
Slug: Ethernaut_wargame19
Authors: F3real
Summary: How to solve Ethernaut wargame lvl. 19

Let's look at the challenge description:
>To solve this level, you only need to provide the Ethernaut with a "Solver", a contract that responds to "whatIsTheMeaningOfLife()" with the right number.

>Easy right? Well... there's a catch.

>The solver's code needs to be really tiny. Really reaaaaaallly tiny. Like freakin' really really itty-bitty tiny: 10 opcodes at most.

Also, we get a hint that we should write our contract hand.

Contracts are created by sending transaction containing contract code and leaving recipient address empty.

Bytecode code sent in this transaction is split in two different parts:

1. *Creation code* - which is executed once during contract creation. It is tasked with setting up initial contract state and returning a copy of runtime code. This code doesn't get saved in contract storage.
2. *Runtime code* - contract code, saved in storage, executed on function calls.

Since there is no state to set, creation code in our case just needs to return a copy of runtime code. To do this we need to use `CODECOPY` and `RETURN`.

    codecopy(t, f, s) 	- 	copy s bytes from code at position f to mem at position t
    return(p, s) 	    - 	end execution, return data mem[p..(p+s))

Let's write our bytecode:

~~~text
;copy bytecode to memory
0x600a     ;PUSH1 0x0a                      S(runtime code size)
0x600d     ;PUSH1 0x0d                      F
0x6000     ;PUSH1 0x00                      T
0x39       ;CODECOPY
;return code from memory to EVM
0x600a     ;PUSH1 0x0a                      S
0x6000     ;PUSH1 0x00                      P
0xf3       ;RETURN
0x00       ;STOP
~~~

In snippet above we copy runtime code to memory and then return copy of it to EVM.

* position F is calculated based on our initialization code size. In our case we have 13 bytes of initialization code after which runtime code starts so its `0x0d`.

EVM will always execute code starting from instruction 0 when contract is called. Usually this first part of runtime code contains function selector, but since we are limited with size, we will just write enough code to return required result (`42` or in hex `0x2a`) no matter what function is called.

To store result in memory, before returning it we have to use `MSTORE`.

    mstore(p, v) 	    - 	mem[p..(p+32)) := v

~~~text
0x602a     ;PUSH1 0x2a
0x6080     ;PUSH1 0x80
0x52       ;MSTORE
0x6020     ;PUSH1 0x20
0x6080     ;PUSH1 0x80
0xf3       ;RETURN
0x00       ;STOP
~~~

We are pushing `0x20` as size since we assume we need to return `uint256` which is 32 bytes long.
So our contract bytecode looks like:
~~~
600a600d600039600a6000f300602a60805260206080f3
<   initalization part   ><   runtime part   >
~~~

To create our contract from console, we can use:

~~~javascript
web3.eth.defaultAccount = web3.eth.accounts[0];
var tx = {
    data : "0x600a600d600039600a6000f300602a60805260206080f3"
}
web3.eth.sendTransaction(tx, (err,res)=>{console.log(err,res);});
~~~

If transaction is successful, we can use etherescan to see created contract address.

Challenge solidity code:
~~~solidity
pragma solidity ^0.4.24;

contract MagicNum {
  address public solver;

  constructor() public {}

  function setSolver(address _solver) public {
    solver = _solver;
  }

  /*
    ____________/\\\_______/\\\\\\\\\_____        
     __________/\\\\\_____/\\\///////\\\___       
      ________/\\\/\\\____\///______\//\\\__      
       ______/\\\/\/\\\______________/\\\/___     
        ____/\\\/__\/\\\___________/\\\//_____    
         __/\\\\\\\\\\\\\\\\_____/\\\//________   
          _\///////////\\\//____/\\\/___________  
           ___________\/\\\_____/\\\\\\\\\\\\\\\_ 
            ___________\///_____\///////////////__
  */
}
~~~

We can use remix to interact with challenge contract and call `setSolver` with address of our contract to win.