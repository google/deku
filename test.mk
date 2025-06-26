# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku

all: test/tags/tags

test/tags/tags: test/tags/src/main.rs
	@cargo -Z unstable-options -C test/tags build
	@mv test/tags/target/debug/tags test/tags/

clean::
	@rm -rf test/tags/target/
	@rm -f test/tags/tags
