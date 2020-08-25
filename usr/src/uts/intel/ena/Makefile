#
# Copyright 20202 Oxide Computer Company
#

UTSBASE = ../..

MODULE		= ena
OBJECTS		= $(ENA_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/ena

include $(UTSBASE)/intel/Makefile.intel

CPPFLAGS	+= -I$(UTSBASE)/common/io/ena

ALL_TARGET	= $(BINARY) $(CONFMOD)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINBAR) $(ROOTMODULE) $(ROOT_CONFFILE)

# XXX pull in common utils?
LDFLAGS		+= -dy -N misc/mac

MAPFILES	+= ddi mac kernel

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

include $(UTSBASE)/Makefile.mapfile
include $(UTSBASE)/intel/Makefile.targ
