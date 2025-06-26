# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku

all: test/tags/tags

test/tags/tags: test/tags/src/main.rs
	cd test/tags; cargo build; cd -
	@mv test/tags/target/debug/tags test/tags/

clean::
	@rm -rf test/tags/target/
	@rm -f test/tags/tags
