# Do not use make's built-in rules
# (this improves performance and avoids hard-to-debug behaviour);
# also do not print "Entering directory..." messages from make
include ../../../Makefile.inc

.SUFFIXES:
MAKEFLAGS += -r --no-print-directory

KCONFIG?=defconfig

ifneq ($(silent),1)
  ifneq ($(V),1)
	QUIET_AUTOCONF       = @echo '  AUTOCONF '$@;
	Q = @
  endif
endif

PREFIX := /usr
BINDIR := $(PREFIX)/bin
INCDIR := $(PREFIX)/include
LIBDIR := $(PREFIX)/lib

ifeq (,$(srctree))
  srctree := $(patsubst %/,%,$(dir $(shell pwd)))
  srctree := $(patsubst %/,%,$(dir $(srctree)))
endif
export srctree

include ../scripts/Makefile.include

# OUTPUT fixup should be *after* include ../scripts/Makefile.include
ifneq ($(OUTPUT),)
  KERNEL_OUT_DIR := $(OUTPUT)
  KOPT += O=$(KERNEL_OUT_DIR)
  OUTPUT := $(OUTPUT)/tools/lkl/
else
  OUTPUT := $(CURDIR)/
endif
export OUTPUT


all:

conf: $(OUTPUT)Makefile.conf

$(OUTPUT)Makefile.conf $(OUTPUT)/kernel.config: Makefile.autoconf
	$(call QUIET_AUTOCONF, headers)$(MAKE) -f Makefile.autoconf -s

include $(OUTPUT)Makefile.conf

export CFLAGS += -I$(OUTPUT)/include -Iinclude -Wall -g -O2 -Wextra \
	 -Wno-unused-parameter \
	 -Wno-missing-field-initializers -fno-strict-aliasing

export CXXFLAGS += -std=c++11 -fPIC -I$(OUTPUT)/include -Iinclude -I$(SYSCALL_DIR) \
	 -Wall -g -O2 -Wextra \
	 -Wno-unused-parameter \
	 -Wno-missing-field-initializers -fno-strict-aliasing

include Targets

# Expand targets to output location and suffix but preserve special
# targets (e.g. .WAIT)
# $1 - targets
# $2 - suffix
expand-targets = $(foreach t,$(1),$(if $(filter .%,$(t)),$(t),$(OUTPUT)$(t)$(2)))

TARGETS := $(call expand-targets,$(progs-y),$(EXESUF))
TARGETS += $(call expand-targets,$(tests-y),$(EXESUF))
TARGETS += $(call expand-targets,$(libs-y),$(SOSUF))
all: $(TARGETS)

# this workaround is for FreeBSD
bin/stat:
ifeq ($(LKL_HOST_CONFIG_BSD),y)
	$(Q)ln -sf `which gnustat` bin/stat
	$(Q)ln -sf `which gsed` bin/sed
else
	$(Q)touch bin/stat
endif

DOT_CONFIG:=$(OUTPUT)../../.config

$(DOT_CONFIG): $(OUTPUT)/kernel.config
	$(Q)$(MAKE) -C ../.. ARCH=lkl $(KOPT) $(KCONFIG)
	$(call QUIET_INSTALL, kernel.config)cat $(OUTPUT)/kernel.config >> $(DOT_CONFIG)
	$(Q)$(MAKE) -C ../.. ARCH=lkl $(KOPT) olddefconfig
	$(Q)$(MAKE) -C ../.. ARCH=lkl $(KOPT) syncconfig

# rule to build lkl.o
$(OUTPUT)lib/lkl.o: bin/stat $(DOT_CONFIG)
# this workaround is for arm32 linker (ld.gold)
	$(Q)export PATH="$(srctree)/tools/lkl/bin/:${PATH}" ;\
	$(MAKE) -C ../.. ARCH=lkl $(KOPT)
	$(MAKE) -C ../.. ARCH=lkl $(KOPT) install INSTALL_PATH=$(OUTPUT)

# rules to link libs
$(OUTPUT)%$(SOSUF): LDFLAGS += -shared
$(OUTPUT)%$(SOSUF): $(OUTPUT)%-in.o $(OUTPUT)liblkl.a
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(LDFLAGS_$*-y) -o $@ $^ $(LDLIBS) $(LDLIBS_$*-y)

# liblkl is special
$(OUTPUT)liblkl$(SOSUF): $(OUTPUT)%-in.o $(OUTPUT)lib/lkl.o
$(OUTPUT)liblkl.a: $(OUTPUT)lib/liblkl-in.o $(OUTPUT)lib/lkl.o
	$(QUIET_AR)$(AR) -rc $@ $^

# rule to link programs
CC := /usr/local/bin/afl-clang-fast
$(OUTPUT)%$(EXESUF): $(OUTPUT)%-in.o $(OUTPUT)liblkl.a
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(LDFLAGS_$*-y) -o $@ $^ $(LDLIBS) $(LDLIBS_$*-y)

# rule to build objects
$(OUTPUT)%-in.o: $(OUTPUT)lib/lkl.o FORCE
	$(Q)$(MAKE) -f $(srctree)/tools/build/Makefile.build dir=$(patsubst %/,%,$(dir $*)) obj=$(notdir $*)


$(OUTPUT)cpfromfs$(EXESUF): cptofs$(EXESUF)
	$(Q)if ! [ -e $@ ]; then ln -s $< $@; fi

# executer's dependencies
$(OUTPUT)Image.o:
	cp -f $(SYSCALL_DIR)/Image.o $@

$(OUTPUT)Program.o:
	cp -f $(SYSCALL_DIR)/Program.o $@

$(OUTPUT)Utils.o:
	cp -f $(SYSCALL_DIR)/Utils.o $@

$(OUTPUT)Constants.o:
	cp -f $(SYSCALL_DIR)/Constants.o $@

LDFLAGS += -fsanitize=undefined

# executor (CPP)
$(OUTPUT)executor: $(OUTPUT)executor-in.o $(OUTPUT)Image.o $(OUTPUT)Program.o $(OUTPUT)Utils.o $(OUTPUT)Constants.o $(OUTPUT)liblkl.a
	$(QUIET_LINK)$(CXX) $(LDFLAGS) $(LDFLAGS_$*-y) -o $@ $^ $(LDLIBS) $(LDLIBS_$*-y)

# combined (CPP)
$(OUTPUT)combined: $(OUTPUT)combined-in.o $(OUTPUT)Image.o $(OUTPUT)Program.o $(OUTPUT)Utils.o $(OUTPUT)Constants.o $(OUTPUT)liblkl.a
	$(QUIET_LINK)$(CXX) $(LDFLAGS) $(LDFLAGS_$*-y) -o $@ $^ $(LDLIBS) $(LDLIBS_$*-y)

# combined-consistency (CPP)
$(OUTPUT)combined-consistency: $(OUTPUT)combined-consistency-in.o $(OUTPUT)Image.o $(OUTPUT)Program.o $(OUTPUT)Utils.o $(OUTPUT)Constants.o $(OUTPUT)liblkl.a
	$(QUIET_LINK)$(CXX) $(LDFLAGS) $(LDFLAGS_$*-y) -o $@ $^ $(LDLIBS) $(LDLIBS_$*-y) -lz

clean:
	$(call QUIET_CLEAN, vmlinux)$(MAKE) -C ../.. ARCH=lkl $(KOPT) clean
	$(call QUIET_CLEAN, objects)find $(OUTPUT) -name '*.o' -delete -o -name '\.*.cmd'\
	 -delete -o -name '\.*.d' -delete
	$(call QUIET_CLEAN, headers)$(RM) -r $(OUTPUT)/include/lkl/
	$(call QUIET_CLEAN, liblkl.a)$(RM) $(OUTPUT)/liblkl.a
	$(call QUIET_CLEAN, targets)$(RM) $(TARGETS) $(FUZZ_TARGETS) bin/stat
	$(call QUIET_CLEAN, gen_protos)$(RM) $(PROTOC_GENERATED_FILES)

mrproper: clean
	$(call QUIET_CLEAN, vmlinux)$(MAKE) -C ../.. ARCH=lkl $(KOPT) mrproper

clean-conf: mrproper
	$(call QUIET_CLEAN, Makefile.conf)$(RM) $(OUTPUT)/Makefile.conf
	$(call QUIET_CLEAN, kernel.config)$(RM) $(OUTPUT)/kernel.config

headers_install: $(TARGETS)
	$(call QUIET_INSTALL, headers) \
	    install -d $(DESTDIR)$(INCDIR) ; \
	    install -m 644 include/lkl.h include/lkl_host.h $(OUTPUT)include/lkl_autoconf.h \
	      include/lkl_config.h $(DESTDIR)$(INCDIR) ; \
	    cp -r $(OUTPUT)include/lkl $(DESTDIR)$(INCDIR)

libraries_install: $(libs-y:%=$(OUTPUT)%$(SOSUF)) $(OUTPUT)liblkl.a
	$(call QUIET_INSTALL, libraries) \
	    install -d $(DESTDIR)$(LIBDIR) ; \
	    install -m 644 $^ $(DESTDIR)$(LIBDIR)

programs_install: $(call expand-targets,$(progs-y),$(EXESUF))
	$(call QUIET_INSTALL, programs) \
	    install -d $(DESTDIR)$(BINDIR) ; \
	    install -m 755 $^ $(DESTDIR)$(BINDIR)

install: headers_install libraries_install programs_install


run-tests:
	./tests/run.py $(tests)

FORCE: ;
.PHONY: all clean clean-conf mrproper FORCE run-tests
.PHONY: headers_install libraries_install programs_install install
.NOTPARALLEL : lib/lkl.o
.SECONDARY:
.WAIT:
