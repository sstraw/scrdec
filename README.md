# scrdec.py
A decoder for dealing with Microsoft Script Encoder.

Microsoft created a script encoder for Javascript and VB scripts, allowing
developers to obfuscate the script while still having cscript and similar
interpreters run it.

While this is less commonly used, it is still available and malware authors
have started using it to obfuscate malicious JS.

These files typically have an extension of .jse or .vbe . Additionally, they
have a "header" of 4 bytes like below
```
$ xxd -l 12 sample_jse
00000000: 2340 7e5e 3341 4541 4141 3d3d            #@~^3AEAAA==
```

Tool:
```
$ ./scrdec.py  -h
usage: scrdec.py [-h] [-i INPUT] [-o OUTPUT]

Decodes scripts encoded by Windows Script Editor

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file. Pipe in for stdin, or specify it with "-"
  -o OUTPUT, --output OUTPUT
                        Output. Writes to stdout by default
```

## Reference:
The below were very helpful in writing this tool
* https://web.archive.org/web/20131208110057/http://virtualconspiracy.com/content/articles/breaking-screnc
* https://gist.github.com/bcse/1834878
