Title: Hollow Knight cheat
Date: 2020-1-21 10:02
Modified: 2020-1-21 10:02
Category: misc
Tags: cheat engine, reversing
Slug: hollowknight
Authors: F3real
Summary: Creating cheat for the Hollow Knight

Hollow Knight is a good Metroidvania game with a great look and atmosphere but it can get annoying due to difficulty. So how to reduce frustration? Well, cheats of course.

There are trainers for Hollow Knight like all other games but it is more fun making your own. So let's look at how to create basic cheat using cheat engine.

I decided to go for two pretty easy cheats:

* gold - stops you from grinding
* health - reduces annoying travel from check-point to the current place (I am not good at jump puzzles).

For these cheats to work we need to find correct offsets. Since the procedure is the same for both, I'll focus only on health since it is a bit harder (the bigger the and the more specific the value you are looking is, it is easier to find).

We are using Hollow Knight Godmaster 1.4.3.2. Offsets can change between versions so it is possible that on a different version of the game you will have to repeat the same procedure.

In the game, we know a number of health (masks) we have. So first, after connecting to the game process, we do a `First Scan` specifying our current number of masks. Now to filter this huger number of results, we have to get hit/heal up a few times. Each time our health changes, we will specify our new health value and use `Next Scan`. In the end, we will have two results but one of these is just display value which is useless. Real value changes immediately on hit while the display one gets updated slightly later. Another way of finding real address is to modify values in Cheat engine and heal up. Healing up triggers display value to be updated, and by looking at how values change we can find real one.

![Cheat Enginer First Scan]({static}/images/2020_1_21_HollowKnight1.png){: .img-fluid .centerimage}

![Cheat Enginer Next Scan]({static}/images/2020_1_21_HollowKnight2.png){: .img-fluid .centerimage}

Now double-clicking on the result, we can add it to the addresslist (bottom pane). Here if we click on the `Active` box on the left of the address we can freeze it. This makes the game unable to update value and effectively gives us infinite health. The only way of dying now is if we take more damage then our frozen health value.

So are we done? Well even if we have functioning health cheat now, simply restarting the game would require us to repeat entire procedure. To make our cheat persist between game runes we have to do a pointer scan.

By right-clicking on address in addresslist, we can select `Pointer scan for this address`.
This will search game memory for all pointers connecting to this address. After this is done, we will reopen the game, reconnect Cheat engine and repeat the same procedure as previously until we find new health address.

![Cheat Enginer Pointer scan]({static}/images/2020_1_21_HollowKnight3.png){: .img-fluid .centerimage}

Now, in Cheat engine, we have to hold `CTRL` and type `mpo` to open Pointer scanner dialog. Here we load previous pointer scan results and then go to a `Rescan memory` to remove pointers from the previous run not pointing to the current health value. Pointers can be found in many different dlls but we know that correct ones are, most probably, in some player dll. In our case, we will focus on UnityPlayer.dll. We can add results we get to the addresslist by double-clicking on them.

![Cheat Enginer Pointer rescan]({static}/images/2020_1_21_HollowKnight4.png){: .img-fluid .centerimage}

Now we probably still have many results, we can try adding them all to the addresslist, running the game a few times and slowly filtering them down or again we can do the same procedure with pointer scan. Anyway, once we filter the results we will get correct pointers (dll + offset) which can be reused each time we start the game.

In my case I have found:
~~~xml

<?xml version="1.0" encoding="utf-8"?>
<CheatTable>
  <CheatEntries>
    <CheatEntry>
      <ID>18</ID>
      <Description>"pointerscan result"</Description>
      <LastState Value="1471" RealAddress="8BB0D118"/>
      <VariableType>4 Bytes</VariableType>
      <Address>"UnityPlayer.dll"+00FEFB58</Address>
      <Offsets>
        <Offset>118</Offset>
        <Offset>2C</Offset>
        <Offset>18</Offset>
        <Offset>44</Offset>
        <Offset>20</Offset>
      </Offsets>
    </CheatEntry>
    <CheatEntry>
      <ID>19</ID>
      <Description>"pointerscan result"</Description>
      <LastState Value="1471" RealAddress="8BB0D118"/>
      <VariableType>4 Bytes</VariableType>
      <Address>"UnityPlayer.dll"+00FFCBF0</Address>
      <Offsets>
        <Offset>118</Offset>
        <Offset>2C</Offset>
        <Offset>18</Offset>
        <Offset>44</Offset>
        <Offset>1C</Offset>
      </Offsets>
    </CheatEntry>
    <CheatEntry>
      <ID>20</ID>
      <Description>"pointerscan result"</Description>
      <LastState Value="1471" RealAddress="8BB0D118"/>
      <VariableType>4 Bytes</VariableType>
      <Address>"UnityPlayer.dll"+00FFCE68</Address>
      <Offsets>
        <Offset>118</Offset>
        <Offset>2C</Offset>
        <Offset>18</Offset>
        <Offset>44</Offset>
        <Offset>10</Offset>
      </Offsets>
    </CheatEntry>
    <CheatEntry>
      <ID>22</ID>
      <Description>"pointerscan result"</Description>
      <LastState Value="8" RealAddress="8BB0D0E4"/>
      <VariableType>4 Bytes</VariableType>
      <Address>"UnityPlayer.dll"+00FEFB58</Address>
      <Offsets>
        <Offset>E4</Offset>
        <Offset>2C</Offset>
        <Offset>18</Offset>
        <Offset>44</Offset>
        <Offset>20</Offset>
      </Offsets>
    </CheatEntry>
    <CheatEntry>
      <ID>23</ID>
      <Description>"pointerscan result"</Description>
      <LastState Value="8" RealAddress="8BB0D0E4"/>
      <VariableType>4 Bytes</VariableType>
      <Address>"UnityPlayer.dll"+00FFCBF0</Address>
      <Offsets>
        <Offset>E4</Offset>
        <Offset>2C</Offset>
        <Offset>18</Offset>
        <Offset>44</Offset>
        <Offset>1C</Offset>
      </Offsets>
    </CheatEntry>
    <CheatEntry>
      <ID>24</ID>
      <Description>"pointerscan result"</Description>
      <LastState Value="8" RealAddress="8BB0D0E4"/>
      <VariableType>4 Bytes</VariableType>
      <Address>"UnityPlayer.dll"+00FFCE68</Address>
      <Offsets>
        <Offset>E4</Offset>
        <Offset>2C</Offset>
        <Offset>18</Offset>
        <Offset>44</Offset>
        <Offset>10</Offset>
      </Offsets>
    </CheatEntry>
  </CheatEntries>
</CheatTable>

~~~