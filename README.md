Make sure you have the libcurl development package installed and then compile with 

`gcc -Wall -nostartfiles -fpic -shared -o httpfs.so httpfs.c func32.c -ldl $(curl-config --libs)` 

use with:

`LD_PRELOAD=./httpfs.so cat http://www.yahoo.com/`

Original text (dup2 / getline / getdelim was added by chx in this repo):

# http-fs-wrapper
Automatically exported from code.google.com/p/http-fs-wrapper

Intercepts the standard C library calls (open / read / lseek / close / fopen / fread / fseek / fclose / ftell / stat / fstat / lstat / dup2 / getline / getdelim) and allows them to transparently access HTTP/HTTPS URLs.

Includes byte-range support for random-access, read-ahead windowing for speed and efficiency, and is built on libcurl, for .. umm .. convenience? :-)
