# Ruby binding for Unicorn engine. Sascha Schirra <sashs@scoding.de>

.PHONY: gen_const

install:
	$(MAKE) gen_const
	C_INCLUDE_PATH=/usr/local/ cd keystone_gem && rake build
	cd keystone_gem && gem install --local pkg/keystone-0.9.0.gem

gen_const:
	cd .. && python const_generator.py ruby
