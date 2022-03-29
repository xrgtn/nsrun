CFLAGS=-g -O0
LDLIBS=-lcap

nsrun: nsrun.c getoptv.c uid_pw.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ $(LDLIBS) -o $@

pxty: pxty.c
	$(CC) $(CPPFLAGS) -O3 $^ -o $@

clean:
	rm -f *.o nsrun pxty
