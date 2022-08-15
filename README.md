# VivisectION

VivisectION is the cross-section of GUI Reversing, Emulation and Debugging, with an emphasis on using Emulation and other powerful Vivisect toys to aid in Reverse Engineering and Vulnerability Research.

Among other things, VivisectION (aka Ion) is a Vivisect Extension (or plugin).

Primarily this plugin allows the GUI to easily setup an emulator for Functions (right click on the Function address)


## Installation:
Install using Pip:
```
    $ pip install VivisectION
```

Alternately, you can install from the latest Github repo (or using a modified form on your local drive):
```
    $ git clone https://github.com/atlas0fd00m/VivisectION
       #(possibly modify anything)
    $ pip install ./VivisectION
```

### You must first activate the plugin:
The following tools will manage a symlink to the plugin directory into $HOME/.viv/plugins/ (or the last directory in your VIV_EXT_PATH)
```
    $ vivisection_activate 
        # and 
    $ vivisection_deactivate
```

## Features:
* Ion Toolbar in Vivisect
* Function Emulation (console) - Right click on the using the console (how you started Vivisect)
* CLI - by clicking the button, users get an interactive python shell in the console (cli you started Vivisect from)


## Future:
* It will also glue debuggers together with Vivisect Server/Shared Workspace

* Debugger attach, dump, and prep for Emulation
    * Import VSNAP, convert to Emu
    * Import GDB Core file, convert to Emu

* Other goodies as I decide to release them (probably expect FuncRecon shortly)



go forth and hack great things!

@

# greetz

* Invisig0th
* Rakuy0
* Sk0d0
* mechanicalnull
* la familia
* the GRIMM team
* Samurai CTF

