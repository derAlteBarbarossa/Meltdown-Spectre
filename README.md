# Meltdown-Spectre

**Discalimer1**: This repository contains my implementation of the 3rd homework for the course *Hardware Security* at ETHZ. All rights shall be reserved for the authors of wom kernel module.

**Discalimer2**: If you are going to take this course, please don't spoil this wonderful experience, by reading this code.

0. Change your VUNETID in the Makefile

1. The wom/ directory contains a kernel module that maps a buffer in memory. The
   goal of the assignment is to leak the contents of this buffer using the Meltdown
   technique. The module is already loaded in kernel memory in all the cluster nodes.
   You can check that by running: 
   
   $ lsmod | grep wom 

3. Now you can build and run the template for the lab assignment in lab3.
   (in the lab3/ dir)
      4a. make
      4b.  $ ./VUNETID-meltdown 
           secret=0xffff8801e318b000
   Your tasks are to leak the content of the buffer pointed to by 'secret' using
   the following Meltdown techniques:

   Task #1/#2: Leak the generated secret using Meltdown with SEGV or TSX
   Task #3: Leak the generated secret using Meltdown in a speculative branch

4. To test your assignment, we will change the contents of this buffer and see
   if your program can leak it correctly. Assume we want to leak the first 32
   bytes of the buffer and that they are all hex digits. Print a newline yourself.

5. If you run:
   
   $ ./test.sh 
   
   The script executes one time your implementation of VUNETID-meltdown_segv, 
   VUNETID-meltdown_tsx and VUNETID-spectre and compares the leaked secret with
   the generated one. The script tells you at the end of each test whether your
   corrisponding implementation is a PASS or FAIL.

5. If you run:
   
   $ ./test.sh batch 
   
   The script executes 100 times your implementation of VUNETID-meltdown_segv, 
   VUNETID-meltdown_tsx and VUNETID-spectre and tells you the success rate of 
   each binary. 
