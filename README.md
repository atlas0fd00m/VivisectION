# vivisection

VivisectION is the cross-section of GUI Reversing, Emulation and Debugging.



TODO:
* Wrap Emutils into this repo
* Rename TestEmulator
* GUI-Emulation integration pieces (external terminal proggy -> Shared Workspace)
* GDB-Vivisect Integration (GDB -> Shared Workspace)



This is going to be a Vivisect plugin.
    Primarily this will use the GUI to launch a terminal window into an Emulator
    How will this get pip-installed?
        vivisection_activate and vivisection_deactivate (which will symlink a plugin directory into $HOME/.viv/plugins/


Maybe not for first release?
* It will also have scripts?  That do what?

* It will also glue debuggers together with Vivisect Server/Shared Workspace

* Debugger attach, dump, and prep for Emulation
    * Import VSNAP, convert to Emu
    * Import GDB Core file, convert to Emu

