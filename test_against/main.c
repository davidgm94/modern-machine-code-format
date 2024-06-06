#include <stdio.h>
extern int library_function(void);
int main(void)
{
    int number = library_function();
    int ascii_number = number + '0';
    fputc(ascii_number, stdout);
    return 0;
}
