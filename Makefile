CFLAGS=-g -O0
LDLIBS=-lcap

nsrun: nsrun.c getoptv.c uid_pw.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

clean:
	rm -f *.o nsrun
