This documentation explains how to install & use PowerShell binding for Keystone.


Install
------

Compile the relevant version (x86/x64) of `keystone.dll` and place it in
`./Keystone/Lib/Keystone/`.

Alternatively, pre-compiled DLL’s can be obtained from the Keystone homepage
at http://keystone-engine.org/download


Usage
-----

To use the PowerShell binding, the entire Keystone folder should be added to
one of the PowerShell module directories:

    # Global PSModulePath path
    %Windir%\System32\WindowsPowerShell\v1.0\Modules

    # User PSModulePath path
    %UserProfile%\Documents\WindowsPowerShell\Modules

Once this is done the module can be initialized by typing “Import-Module Keystone”
in a new PowerShell terminal. Further information on the usage of the binding
can be obtained with the following command:

    Get-Help Get-KeystoneAssembly -Full


Notes
-----

The Keystone engine requires the Visual C++ Redistributable Packages for Visual
Studio 2013. The architecture relevant installer can be downloaded at the
URL https://www.microsoft.com/en-gb/download/confirmation.aspx?id=40784
