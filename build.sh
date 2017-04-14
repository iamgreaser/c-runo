#!/bin/sh

cc -std=c99 -Wall -Wextra -pedantic -Os -g -fPIC -shared -o libetty.so src/etty.c && \
cc -std=c99 -Wall -Wextra -pedantic -Os -g -o c-runo src/server.c -pthread -ldl && \
cc -std=c99 -Wall -Wextra -pedantic -Os -g -fPIC -shared -o examples/hello/hello-worker.so examples/hello/worker.c -Isrc/ -Wl,-rpath,. -L. -letty && \
true

