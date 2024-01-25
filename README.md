# CFuzz (alpha)

For now this is prototype for harness function generator for C++ class using libclang

Main advantage: usage of method combinations while fuzzing

**further development will be moved to new repository**

## Structure and files

Jinja2 - template for future integration with jinja2

targets - classes used for hand-testing

coder.c - encode/decode call chain

main.c - harness function generator

mutfuzz - custom mutator for callchain
