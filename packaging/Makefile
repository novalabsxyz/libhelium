OS            = $(shell uname -s)
PKG_REVISION  ?= $(shell git describe --tags)

# Default the package build version to 1 if not already set
PKG_BUILD    ?= 1

# Flags that are shared on all platforms, this MUST go last
SHAREDFLAGS   = -s dir -m 'packaging@helium.co' -a native -n libhelium \
		-v $(PKG_REVISION) -C ./stage --iteration $(PKG_BUILD) \
		--license MIT --vendor Helium \
		-x .git \
		include lib

ifeq ($(OS),Linux)
ARCH          = $(shell uname -m)
ISRPM         = $(shell cat /etc/redhat-release 2> /dev/null)
ISDEB         = $(shell cat /etc/debian_version 2> /dev/null)
ISSLES        = $(shell cat /etc/SuSE-release 2> /dev/null)
ifneq ($(ISRPM),)
OSNAME        = RedHat
PKGTYPE       = rpm
OUTTYPE       = -t $(PKGTYPE)
else
ifneq ($(ISDEB),)
OSNAME        = Debian
PKGTYPE       = deb
OUTTYPE       = -t $(PKGTYPE)
else
ifneq ($(ISSLES),)
OSNAME        = SLES
PKGTYPE       = rpm
OUTTYPE       = -t $(PKGTYPE)
endif  # SLES
endif  # deb
endif  # rpm
endif  # linux

ifeq ($(OS),Darwin)          # OSX
OSNAME        = OSX
ARCH          = $(shell file `which cc` | grep -c x86_64 2> /dev/null | awk \
                       '{if ($$1 == "0") {print "i386"} else {print "x86_64"}}')
PKGTYPE       = tar
OUTTYPE       = -t $(PKGTYPE)
PKGOPTIONS    = --prefix=/usr/local
BUILDCMD      =  $(OUTTYPE) $(PKGOPTIONS) $(SHAREDFLAGS)
endif

ifeq ($(OS),FreeBSD)
OSNAME        = FreeBSD
ARCH          = $(shell uname -m)
PKGNG         = $(shell uname -r | awk -F. '{ print ($$1 > 9) ? "true" : "false" }')
ifeq ($(PKGNG),true)        # FreeBSD 10.0 or greater
PKGTYPE       = fbsdng
else                        # Older FreeBSD pkg_add
PKGTYPE       = fbsd
endif
endif

ifeq ($(OS),SunOS)         # Solaris flavors
KERNELVER     = $(shell uname -v | grep -c joyent 2> /dev/null)
ARCH          = $(shell file `which erlc` | grep -c 64-bit 2> /dev/null | awk \
                    '{if ($$1 == "0") {print "i386"} else {print "x86_64"}}')

ifneq ($(KERNELVER),0)       # SmartOS
OSNAME        = SmartOS
PKGTYP E      = smartos
else                         # Solaris / OmniOS
DISTRO        = $(shell head -1 /etc/release|awk \
                   '{if ($$1 == "OmniOS") {print $$1} else {print "Solaris"}}')
OSNAME        = ${DISTRO}
PKGTYPE       = solaris
endif

endif



.PHONY: ostype varcheck package

package: ostype install
	fpm $(BUILDCMD)

install: stage
	cd .. && make install
stage:
	cmake -DCMAKE_INSTALL_PREFIX:PATH=./stage ..

ostype: varcheck supported
	@echo "Operating system: '$(OSNAME)', '$(OS)', '$(ARCH)'"
	@echo "Build type: '$(PKGTYPE)'"
	@echo "Build command: '$(BUILDCMD)'"

supported:
	$(if $(BUILDCMD),,$(error "Operating system '$(OSNAME)' not supported by libhelium"))


## Check required settings before continuing
varcheck:
	$(if $(shell which fpm),,$(error "FPM is needed to build packages, see https://github.com/jordansissel/fpm"))
