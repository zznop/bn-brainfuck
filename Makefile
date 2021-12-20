.PHONY: install uninstall

# default target if listed first, displays error message
error:
	@echo "available targets: install, uninstall"
	@exit -1

# install/uninstall via link
install:
	@if [ -L "$(BN_PLUGINS)/bn-brainfuck" ]; then \
		echo "already installed"; \
	else \
		echo "installing"; \
		ln -s "$(PWD)" "$(BN_PLUGINS)/bn-brainfuck"; \
	fi

uninstall:
	@if [ -L "$(BN_PLUGINS)/bn-brainfuck" ]; then \
		echo "uninstalling"; \
		rm "$(BN_PLUGINS)/bn-brainfuck"; \
	else \
		echo "not installed"; \
	fi

