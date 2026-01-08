.PHONY: all clean run

TEST_MAKEFILES := $(wildcard Makefile.*)
TEST_TARGETS := $(patsubst Makefile.%, test_%, $(TEST_MAKEFILES))

all: $(TEST_TARGETS)

$(TEST_TARGETS): test_%: Makefile.%
	$(MAKE) -f $<

run: $(TEST_TARGETS)
	@for mkfile in $(TEST_MAKEFILES); do \
		$(MAKE) -f $$mkfile run; \
		done

clean:
	@for mkfile in $(TEST_MAKEFILES); do \
		$(MAKE) -f $$mkfile clean; \
		done
