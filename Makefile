python := python3
src_dir := quic

virtualenv_dir := pyenv
pip := $(virtualenv_dir)/bin/pip
pytest := $(virtualenv_dir)/bin/py.test
coverage := $(virtualenv_dir)/bin/coverage


test:
	test_type=unit $(MAKE) test-base
	test_type=integration $(MAKE) test-base

test-base: $(virtualenv_dir)
	PYTHONPATH=$(PYTHONPATH):. $(coverage) run \
		--source $(src_dir) $(pytest) -s tests/$(test_type)
	$(coverage) report -m
.PHONY: test

$(virtualenv_dir): requirements/dev.txt requirements/prod.txt
	virtualenv $@ --python=$(python)
	for r in $^ ; do \
		$(pip) install -r $$r ; \
	done
