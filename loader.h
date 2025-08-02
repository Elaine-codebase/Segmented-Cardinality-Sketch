#include <iostream>
#include <stdint.h>
#include <string.h>

// 源目的ip+时间戳
typedef struct
{
    uint64_t item;      // 源目的ip
    uint64_t timestamp; // 时间戳
} dataItem;

// 数据加载类
class Loader
{
    typedef struct
    {
        unsigned char *databuffer;
        uint64_t cnt = 0;
        uint64_t cur = 0;
        unsigned char *ptr;
    } loader;

public:
    Loader(std::string filename, uint64_t buffersize);
    ~Loader();

    int GetNext(dataItem *dataitem);
    void Reset();
    uint64_t GetDataSize();
    uint64_t GetCurrent();

private:
    loader *data;
};