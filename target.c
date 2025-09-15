#include <unistd.h>
#include <stdio.h>

char garbage[0x10];

int main(int argc, char** argv){
    read(STDIN_FILENO, garbage, 0x10);
    fwrite("argh", 4, 1, stdout);
    return 0;
}