# Build and install the C library (Linux, macOS, BSD; Windows: see README).
#
#   make                                 build shared and static libraries
#   sudo make install                    install library, header, pkg-config
#                                        file and CMake package
#   sudo make uninstall
#
# PREFIX (default /usr/local), LIBDIR, INCLUDEDIR and DESTDIR are honoured,
# as are CARGO and CARGO_FLAGS (e.g. CARGO_FLAGS=--offline).

PREFIX      ?= /usr/local
LIBDIR      ?= $(PREFIX)/lib
INCLUDEDIR  ?= $(PREFIX)/include
DESTDIR     ?=
CARGO       ?= cargo
CARGO_FLAGS ?=
PROFILE     ?= release
TARGET_DIR  ?= target/c

VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
ABI     := $(shell sed -n 's/^\#define SMPTE_KLV_ABI_VERSION \([0-9][0-9]*\).*/\1/p' include/smpte_klv.h)
OUT     := $(TARGET_DIR)/$(if $(filter dev,$(PROFILE)),debug,$(PROFILE))
SOURCES := Makefile Cargo.toml $(wildcard Cargo.lock) include/smpte_klv.h $(shell find src -name '*.rs')

ifeq ($(shell uname -s),Darwin)
  BUILT_SHARED := libsmpte_klv.dylib
  SHARED       := libsmpte_klv.$(ABI).dylib
  LINK_NAME    := libsmpte_klv.dylib
  SONAME       := @rpath/$(SHARED)
  SONAME_ARG   := -Wl,-install_name,$(SONAME)
else
  BUILT_SHARED := libsmpte_klv.so
  SHARED       := libsmpte_klv.so.$(ABI)
  LINK_NAME    := libsmpte_klv.so
  SONAME       := $(SHARED)
  SONAME_ARG   := -Wl,-soname,$(SONAME)
endif

SHARED_LIB := $(OUT)/$(BUILT_SHARED)
STATIC_LIB := $(OUT)/libsmpte_klv.a
# The system libraries the static library needs, as rustc reports them.
NATIVE     := $(OUT)/native-static-libs
CMAKE_DIR  := $(LIBDIR)/cmake/smpte_klv

SUBST = sed -e 's|@VERSION@|$(VERSION)|g' -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@LIBDIR@|$(LIBDIR)|g' \
	-e 's|@INCLUDEDIR@|$(INCLUDEDIR)|g' -e 's|@SHARED@|$(SHARED)|g' -e 's|@SONAME@|$(SONAME)|g' \
	-e "s|@NATIVE_LIBS@|$$(cat $(NATIVE))|g" \
	-e "s|@NATIVE_LIBS_CMAKE@|$$(sed -e 's/-framework /-framework@/g' -e 's/ /;/g' -e 's/@/ /g' $(NATIVE))|g"

.PHONY: all install uninstall clean check

all: $(SHARED_LIB) $(STATIC_LIB)

# Cargo may leave an up-to-date file untouched, hence the touch.
$(SHARED_LIB): $(SOURCES)
	@test -n "$(VERSION)" -a -n "$(ABI)" || { echo "cannot read the version from Cargo.toml and include/smpte_klv.h"; exit 1; }
	$(CARGO) rustc --color never $(CARGO_FLAGS) --features capi --lib --profile $(PROFILE) --crate-type cdylib --target-dir $(TARGET_DIR) \
		-- -C link-arg=$(SONAME_ARG) -C strip=symbols
	@touch $@

$(STATIC_LIB): $(SOURCES)
	@mkdir -p $(OUT)
	$(CARGO) rustc --color never $(CARGO_FLAGS) --features capi --lib --profile $(PROFILE) --crate-type staticlib --target-dir $(TARGET_DIR) \
		-- --print native-static-libs 2> $(OUT)/staticlib.log || { cat $(OUT)/staticlib.log; exit 1; }
	@sed -n 's/^note: native-static-libs: //p' $(OUT)/staticlib.log | tail -n 1 > $(NATIVE)
	@test -s $(NATIVE) || { echo "rustc did not report the static library's system libraries"; exit 1; }
	@touch $@

install: all
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR) $(DESTDIR)$(LIBDIR)/pkgconfig $(DESTDIR)$(CMAKE_DIR)
	install -m 755 $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/$(SHARED)
	ln -sf $(SHARED) $(DESTDIR)$(LIBDIR)/$(LINK_NAME)
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/libsmpte_klv.a
	install -m 644 include/smpte_klv.h $(DESTDIR)$(INCLUDEDIR)/smpte_klv.h
	@echo "generating $(DESTDIR)$(LIBDIR)/pkgconfig/smpte_klv.pc and $(DESTDIR)$(CMAKE_DIR)/*.cmake"
	@$(SUBST) c/smpte_klv.pc.in > $(DESTDIR)$(LIBDIR)/pkgconfig/smpte_klv.pc
	@$(SUBST) c/smpte_klv-config.cmake.in > $(DESTDIR)$(CMAKE_DIR)/smpte_klv-config.cmake
	@$(SUBST) c/smpte_klv-config-version.cmake.in > $(DESTDIR)$(CMAKE_DIR)/smpte_klv-config-version.cmake

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(SHARED) $(DESTDIR)$(LIBDIR)/$(LINK_NAME) $(DESTDIR)$(LIBDIR)/libsmpte_klv.a
	rm -f $(DESTDIR)$(INCLUDEDIR)/smpte_klv.h $(DESTDIR)$(LIBDIR)/pkgconfig/smpte_klv.pc
	rm -f $(DESTDIR)$(CMAKE_DIR)/smpte_klv-config.cmake $(DESTDIR)$(CMAKE_DIR)/smpte_klv-config-version.cmake
	-rmdir $(DESTDIR)$(CMAKE_DIR) 2>/dev/null

check:
	bash tests/c/check-package.sh

clean:
	rm -rf $(TARGET_DIR)
