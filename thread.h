#include <stdbool.h>
#include <Block.h>


typedef void (^thread_body)(void);

void thread(thread_body tb);
