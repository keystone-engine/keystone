require 'mkmf'

extension_name = 'keystone'

dir_config(extension_name)
have_library('keystone')

create_makefile(extension_name)