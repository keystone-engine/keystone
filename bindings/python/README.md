To install Python binding from Pypi (binary), simply do:

        pip install keystone-engine


In case you want to install from source code, follow the below steps.


0. Install the core engine as dependency

   Follow README.md in the root directory to compile & install the core.


1. To install pure Python binding on *nix, run the command below in the Python bindings directory:

        $ sudo make install

  To install Python3 binding package, run the command below:
  (Note: this requires python3 installed in your machine)

        $ sudo make install3

  For example how to use Keystone API, see sample.py


2. To install Python binding on Windows:

  Run the following command in command prompt:

        C:\> C:\location_to_python\python.exe setup.py install

  Next, copy all the DLL files from the 'Core engine for Windows' package available
  on the same Keystone download page and paste it in the path:

        C:\location_to_python\Lib\site-packages\keystone\
