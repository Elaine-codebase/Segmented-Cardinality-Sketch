#include "loader.h"

// 读取数据
Loader::Loader(std::string filename, uint64_t buffersize) {
    data = (loader *)calloc(1, sizeof(loader)); // 数据指针
    data->databuffer = (unsigned char *)calloc(buffersize, sizeof(unsigned char));
    data->ptr = data->databuffer;
    data->cnt = 0;
    data->cur = 0;
    // 读取dat文件
    FILE *infile = fopen(filename.c_str(), "rb");
    if (!infile) {
        std::cerr << "Unable to open dat file for reading.\n";
        exit(-1);
    }

    // 独立于data->ptr的指针
    unsigned char *p = data->databuffer;
    // 遍历dat文件
    while (!feof(infile)) {
        uint64_t item;      // 源目的ip
        uint64_t timestamp; // 时间戳

        size_t item_size = fread(&item, sizeof(item), 1, infile);
        size_t timestamp_size = fread(&timestamp, sizeof(timestamp), 1, infile);

        if (item_size != 1 || timestamp_size != 1)
            break;

        memcpy(p, &item, sizeof(item));
        memcpy(p + sizeof(uint64_t), &timestamp, sizeof(timestamp));
        p += sizeof(item) + sizeof(timestamp);
        data->cnt++;
    } // end while
    
    fclose(infile);
    std::cout << "[Message] Read " << data->cnt << " items." << std::endl;
}

// 析构函数
Loader::~Loader() {
    free(data->databuffer);
    free(data);
}

// 获取下一条数据
int Loader::GetNext(dataItem *dataitem) {
    if (data->cur >= data->cnt)
    {
        return -1; // 已读取完数据则返回-1
    }

    // 获取相关数据
    dataitem->item = *((uint64_t *)data->ptr);
    dataitem->timestamp = *((uint64_t *)(data->ptr + sizeof(uint64_t)));

    // 更新计数器和指针
    data->cur ++;
    data->ptr += sizeof(uint64_t) * 2;

    // 成功读取则返回1
    return 1;
}

// 重置数据
void Loader::Reset() {
    data->cur = 0;
    data->ptr = data->databuffer;
}

// 获取数据条目
uint64_t Loader::GetDataSize() {
    return data->cnt;
}

uint64_t Loader::GetCurrent() {
    return data->cur;
}