CFLAGS += -O0
CFLAGS += -Iinclude
CFLAGS += -D_GNU_SOURCE=1

LDFLAGS += -no-pie

VUNETID = bgs137

all: check $(VUNETID)-meltdown_segv $(VUNETID)-spectre

check:
ifndef VUNETID
		$(error VUNETID is undefined. Please specify it in the Makefile.)
endif

$(VUNETID)-meltdown_segv: main-meltdown_segv.o
	${CC} $< -o $@ ${LDFLAGS} ${CFLAGS} ${LIBS}

#$(VUNETID)-meltdown_tsx: main-meltdown_tsx.o
#	${CC} $< -o $@ ${LDFLAGS} ${CFLAGS} ${LIBS}

$(VUNETID)-spectre: main-spectre.o
	${CC} $< -o $@ ${LDFLAGS} ${CFLAGS} ${LIBS}

%.o: %.c
	${CC} -c $< -o $@ ${CFLAGS} -MT $@ -MMD -MP -MF $(@:.o=.d)

clean: check
	rm -f $(VUNETID)-* *.o *.d
