#include <stdlib.h>
#include <stdio.h>

#define REQUIRED_ARGS \
    REQUIRED_STRING_ARG(interface, "interface", "Interface name")

#define BOOLEAN_ARGS \
    BOOLEAN_ARG(help, "-h", "Show help")

#include "easyargs.h"

int main(int argc, char** argv)
{
    args_t args = make_default_args();
    int spongebob = 0;

    if (!parse_args(argc, argv, &args) || args.help)
    {
        print_help(argv[0]);

        return EXIT_FAILURE;
    }

    printf("Vile Machinations!!!\n");

    return EXIT_SUCCESS;
}
