#include <server.hpp>

int main(int argc, char** argv)
{
    using namespace dweb;

    Server server;
    server.run();
    return 0;
}