#include <bitcoinconsensus.h>

int main(void)
{
    return bitcoinconsensus_version() == BITCOINCONSENSUS_API_VER ? 0 : 1;
}
