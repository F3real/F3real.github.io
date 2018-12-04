Title: CS 1.6 Steam ID Changer
Date: 2018-12-3 10:01
Modified: 2018-12-3 10:01
Category: reversing
Tags: cs 1.6, reversing, cheat engine
Slug: CS1.6_SteamID
Authors: F3real
Summary: How to change steamID for non-steam CS 1.6 version

Cs 1.6 is FPS that got released in 2000, but it is still played both on steam and non-steam servers.
This post will be focused on finding way to unban ourselfs while using non-steam version of game.
Required software:

* Cheat Engine 6.8.1
* Cs 1.6 Warzone Build 4554

Browsing posts about SteamID internet we see that there are few different ways being mentioned that admins can use to ban players from their server:

* SteamID
* MAC
* IP
* HWID (Hard disk volume ID)

SteamID is not static value for non-steam players, even reinstaling game can change it. Plugins can also use custom ways of calculating it so same player can have 2 different SteamIDs on two different servers.

To check our SteamID, we can just type `status` in console (opens with `~`)
after connecting to game (either local or online).

First step of changing our ID is to locate it in memory. For this, we can use Cheat Engine. After connection to process we can just search for value we have gotten from `status` command.

<p align="center">
<img class="img-fluid" alt="Opening process in CheatEngine" src="{static}/images/3_12_OpeningProcess_CheatEngine.png">
</p>

As we see address is not fixed, rather it is in form base dll  + offset
(`steamclient.dll + 0x5AC4C`).

<p align="center">
<img class="img-fluid" alt="Opening process in CheatEngine" src="{static}/images/3_12_FindingMemoryAddress_CheatEngine.png">
</p>

Now we can simply change this value to get ourselfs unbanned from most servers, but there are few interesting things worth mentioning.
* SteamID is only set after you first enter server (either local or online). Changing value before will just result in it being overwritten after we enter server.
* If server is using custom way to calculate SteamID we won't be able to find that value in memory (at least in my testing), but still changing our local SteamID will affect it so it is probably derived in some way from it.
Best way to find location of SteamID (local one) is therefore to create local server and check it.

Since we know location of our SteamID we can automate process of changing it.
CheatEngine gives us ability to write Lua scripts (`Table->Show Cheat Table Lua Script`).
CheatEngine is not most documented software, but browsing trough forum it is easy to find enough to write our exploit.

~~~lua
    function openCS()
        procFound = openProcess("hl.exe");
        if procFound then
            return true
        end
        return false
    end

    function changeSteamID()
        if not openCS() then
            return nil
        end
        current_SteamID = readSteamID()
        print(current_SteamID)
        writeInteger(steamID_addr, current_SteamID + 1)
        print(readSteamID())
    end

    function getSteamIDAddress()
        steamID_addr_offset = 0x5AC4C
        steamClient_addr = getAddress("steamclient.dll")
        steamID_addr = steamID_addr_offset + steamClient_addr
        return steamID_addr
    end

    function readSteamID()
        current_SteamID = readInteger(getSteamIDAddress())
        return current_SteamID
    end
    changeSteamID()
~~~

We can save created script as `.CETRAINER` so we can run it without starting whole CheatEngine.
