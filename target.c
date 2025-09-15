#include <unistd.h>

char garbage[0x10];

int main(int argc, char** argv){
    read(STDIN_FILENO, garbage, 0x10);
    return 0;
}