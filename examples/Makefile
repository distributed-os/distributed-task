CC := gcc
Q := @

TARGET := simple-cmd simple-task multi-task task-memory task-mmap file-ops

all: ${TARGET}

simple-cmd: simple-cmd.c
	$(Q) echo "  CC      " $@
	$(Q) ${CC} $^ -o $@ -g -lrt -I../dtt/include -L../dtt/lib -l:libdtt.a

simple-task: simple-task.c
	$(Q) echo "  CC      " $@
	$(Q) ${CC} $^ -o $@ -g -lrt -I../dtt/include -L../dtt/lib -l:libdtt.a

multi-task: multi-task.c
	$(Q) echo "  CC      " $@
	$(Q) ${CC} $^ -o $@ -g -lrt -I../dtt/include -L../dtt/lib -l:libdtt.a

task-memory: task-memory.c
	$(Q) echo "  CC      " $@
	$(Q) ${CC} $^ -o $@ -g -lrt -I../dtt/include -L../dtt/lib -l:libdtt.a

task-mmap: task-mmap.c
	$(Q) echo "  CC      " $@
	$(Q) ${CC} $^ -o $@ -g -lrt -I../dtt/include -L../dtt/lib -l:libdtt.a

file-ops: file-ops.c
	$(Q) echo "  CC      " $@
	$(Q) ${CC} $^ -o $@ -g -lrt -I../dtt/include -I../dtt -L../dtt/lib -l:libdtt.a

clean:
	$(Q) rm -rf ${TARGET}
