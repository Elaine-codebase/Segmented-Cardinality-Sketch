#include <iostream>
#include <random>
#include <queue>
#include "hash.h"
#include "bucket.h"
#include "loader.h"

#include <arpa/inet.h>  // for inet_pton, inet_ntop
#include <netinet/in.h> // for in_addr
#include <cstring>      // for memset
using namespace std;

#define BFSEED 1001
// 编译指令：g++ -Wall -o main.out main.cpp hash.cpp loader.cpp -lpcap


#include <vector>
#include <iostream>
#include <chrono>

string int_to_ip(uint32_t ip_int) {
    struct in_addr ip_addr;
    ip_addr.s_addr = htonl(ip_int); // 转为网络字节序
    char buf[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &ip_addr, buf, INET_ADDRSTRLEN)) {
        throw runtime_error("Conversion failed");
    }
    return string(buf);
}



std::string indent(int level) {
    return std::string(level * 2, ' ');
}

// 核心递归函数，带结构输出
int check_recursive(std::vector<bool>& bitmap, int left, int right, int depth ) {
   if(left>=right-1){

    //std::cout<<"end"<<left<<" "<<right<<" "<<depth<<std::endl;
   return depth;}
    int mid = (left + right) / 2;

    bool left_has = false;

    for (int i = left; i <mid; ++i) {
        if (bitmap[i]) {
            left_has = true;
            break;
        }
    }

    bool right_has = false;
    for (int i = mid; i <right; ++i) {
        if (bitmap[i]) {
            right_has = true;
            break;
        }
    }

    if (left_has && right_has) {

   // std::cout<<"end"<<left<<" "<<right<<" "<<depth<<std::endl;
        return depth;
    }

    if (left_has) {
        return check_recursive(bitmap,left,mid,depth+1);
      
    }
    if(right_has)return check_recursive(bitmap, mid, right, depth + 1);
    
}

// 包装函数

double QueryLC(const std::vector<bool>& bitmap) {
    int b = bitmap.size();
    int z = 0;
    for (int i = 0; i < b; ++i) {
        if (!bitmap[i]) z++;
    }

    // 防止 ln(0) 错误
    if (z == 0) z = 1;

    return b * std::log(static_cast<double>(b) / z);
}

int main() {
    // 0.真实数据
    const string real[70] = {
    //"132.142.10.1",
    "123.45.67.89","120.45.67.89","48.20.240.5","100.0.0.1","192.168.200.25","207.56.89.12",
    "9.12.45.87","79.50.23.15","150.128.34.56","180.64.150.30","66.66.123.222","1.2.3.4","90.127.254.13",
    "198.51.100.203","230.100.3.45","23.100.88.99","121.0.113.45","84.6.8.200","45.19.201.250","237.63.111.111",
    "82.98.255.33","43.90.110.9","47.247.197.194","14.10.11.219","8.68.194.246","174.97.27.49",
     "54.163.145.8","187.2.27.144","188.28.61.164","8.52.110.122","200.233.140.100",
     "205.155.210.84","68.100.27.118","108.2.148.61","51.11.76.231","164.57.249.195","102.58.19.90",
     "122.61.235.72","94.228.10.51","168.243.56.16","6.78.188.160","6.69.227.10","153.172.111.153",
     "4.71.121.40","18.103.253.18","215.179.106.14","150.24.185.117","164.48.124.233","21.146.112.3",
     "176.119.41.86","44.192.36.20","166.35.183.195","88.36.49.157","51.172.81.7","47.255.92.140",
     "127.82.222.232","31.204.192.2","101.167.51.236","179.245.215.236","91.73.118.25","182.75.67.47",
     "106.36.68.194","74.204.161.89","152.14.104.54","216.170.99.145","24.68.107.167","184.139.55.102",
     "93.132.19.157","157.250.232.126","75.195.216.94"
     
     };

    // 1.配置相关参数
    const int rowSize = 4;  // Bucket Matrix的行数 8kb
    const int colSize = 32;  // Bucket Matrix的列数
    const size_t bitmapSize = 400;//307   *2*2*2*2*2*2;  // 位图的大小 1/4KB
    const int group = 6;  // 每组的bit数 4
    const int segments = 32 / group;  // 每组group bit，共32/group段
    const unsigned long long bufferSize = 5000000000;  // 读取数据的缓存大小
    const int threshold = 20;  // 阈值
    std::cout << "[Message] Threshold: " << threshold << ".\n";

    // 1.1.随机数
    std::random_device rd;  // 随机种子
    std::mt19937 gen(rd());  // 使用Mersenne Twister算法
    std::uniform_int_distribution<> intDis(0, rowSize - 1);  // 生成0到rowSize-1之间的随机整数
    std::uniform_real_distribution<> realDis(0.0, 1.0);  // 生成0到1之间的随机浮点数

    // 1.2.大根堆（参数：元素类型，容器类型，排序方式）
    std::priority_queue<Bucket::bucket, std::vector<Bucket::bucket>, Bucket::CompareBucket> maxHeap;
    
    // 2.初始化相关数据结构
    // （1）创建rowSize行colSize列的Bucket Matrix
    std::vector<std::vector<Bucket::bucket>> bucketArray(rowSize, std::vector<Bucket::bucket>(colSize));

    // （2）初始化Bucket Matrix的每个bucket对象
    for (int i = 0; i < rowSize; ++i) {
        for (int j = 0; j < colSize; ++j) {
            // 参数：源ip、位图大小以及倾斜度
            bucketArray[i][j] = Bucket::bucket(0, bitmapSize, 0);
        }
    }
    std::cout << "[Message] Done Initializing Bucket Matrix." << std::endl;

    // 3.读取并处理数据
    Loader *loader = new Loader("caida501.dat", bufferSize);
    dataItem item;
    loader->Reset();
    uint16_t scount=0;

    uint16_t wrcount=0;
    uint16_t sxcount=0;
    std::cout << "[Message] Start Processing Data." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
 int cooun=0;
    while (loader->GetNext(&item) == 1)
    {   uint32_t srcc=(item.item >> 32)& 0xFFFFFFFF;
//（1）选桶
cooun+=1;
        int emptyCount = 0; // 记录rowSize行中的桶的空缺数
        bool found = false; // 记录是否匹配到源ip相同的桶
        Bucket::bucket *operate_bucket = nullptr; // 待操作的桶
        uint32_t src = (item.item >> 32) & 0xFFFFFFFF; // 源IP
        uint32_t dst = item.item & 0xFFFFFFFF; // 目的IP
        for (int i = 0; i < rowSize; i++) {
            uint64_t hash_result = (Hash::BOBHash64((uint8_t*)&src, sizeof(u_int64_t), i+BFSEED))% colSize;//hash_combined(src, i) % colSize;
            // 源ip相同
              //if(check_recursive(bucketArray[i][hash_result].oldbitmap,0,128,0)==7)
            //{
              //  found = true;
                // std::cout << src << "选择第" << i+1 << "行的第" << hash_result+1 << "个桶.\n";
                // 将该桶的地址赋值给待操作的桶.
                //operate_bucket = &bucketArray[i][hash_result];

                //operate_bucket->sourceIP=src;
                //break;
            //}
            if (bucketArray[i][hash_result].sourceIP == src) {
                found = true;
                bucketArray[i][hash_result].count+=1;
                // std::cout << src << "选择第" << i+1 << "行的第" << hash_result+1 << "个桶.\n";
                // 将该桶的地址赋值给待操作的桶
           operate_bucket = &bucketArray[i][hash_result];
           double zero=std::count(bucketArray[i][hash_result].bitmap.begin(), bucketArray[i][hash_result].bitmap.end(), false);
           
           if((std::find(std::begin(real), std::end(real), int_to_ip(bucketArray[i][hash_result].sourceIP)) != std::end(real)))

          // std::cout<<"check"<<int_to_ip(src)<<"number"<<256-zero<<"count"<<bucketArray[i][hash_result].count<<std::endl;
           
                break;
            } else if (bucketArray[i][hash_result].sourceIP != 0) {
                continue;
            } else {
            // 桶为空
                // std::cout << "桶为空.\n";
                emptyCount += 1;
            }
        }

        //（1.1）存在空桶，随机插入某个桶
        if (emptyCount > 0 && !found) {
            for (int i = 0; i < rowSize; i++) {
        
            uint64_t hash_result = (Hash::BOBHash64((uint8_t*)&src, sizeof(u_int64_t), i+BFSEED))% colSize;//hash_combined(src, i) % colSize;
            // 随机插入某个桶
            if (bucketArray[i][hash_result].sourceIP == 0) {
                // std::cout << "随机选择第" << i+1 << "行的第" << hash_result+1 << "个桶.\n"; 
                bucketArray[i][hash_result].sourceIP = src;
                bucketArray[i][hash_result].count=1;
                operate_bucket = &bucketArray[i][hash_result];
                break;
            } //else {
               // while (bucketArray[i][hash_result].sourceIP != 0) {
                    
                 //   i = intDis(gen);
                   // std::cout<<"te"<<i<<std::endl;
                  //  hash_result = (Hash::BOBHash64((uint8_t*)&src, sizeof(u_int64_t), i+BFSEED))% colSize;//hash_combined(src, i) % colSize;
               // }
                // std::cout << "随机选择第" << i+1 << "行的第" << hash_result+1 << "个桶.\n"; 
               // bucketArray[i][hash_result].sourceIP = src;
                 //      bucketArray[i][hash_result].count=1;
                //operate_bucket = &bucketArray[i][hash_result]; break;
            //}         
            }
        }

        //（1.2）三桶均满且源IP与item的源ip不同，替换
        if (emptyCount == 0 && !found && operate_bucket == nullptr) {
            int min = 65536;
            int minIndex = 65536;
            //uint64_t specific_hash_result;  // 具体的替换位置
            for (int i = 0; i < rowSize; i++) {
             // while (bucketArray[i][hash_result].sourceIP != 0) {
                    
                i = intDis(gen);
                uint64_t hash_result = (Hash::BOBHash64((uint8_t*)&src, sizeof(u_int64_t), i+BFSEED))% colSize;//hash_combined(src, i) % colSize;
              // if(bucketArray[i][hash_result].sourceIP!=0){
            //std::vector<bool> union_bit= bitmap_union((&bucketArray[i][hash_result])->bitmap,(&bucketArray[i][hash_result])->oldbitmap);
            double zero=std::count(bucketArray[i][hash_result].bitmap.begin(), bucketArray[i][hash_result].bitmap.end(), false);
            double zero1=std::count(bucketArray[i][hash_result].oldbitmap.begin(), bucketArray[i][hash_result].oldbitmap.end(), false);            
            //std::cout<<"tihuan"<<"i="<<int_to_ip(bucketArray[i][hash_result].sourceIP)<<" "<<zero<<" "<<zero1<<" "<<hash_result<<std::endl;
            double total=bucketArray[i][hash_result].bitmap.size()*std::log(float(bucketArray[i][hash_result].bitmap.size())/float(zero));
            
            double score=float(total)*float(std::log(total+2));///float(1 << (32-4*1));
            //if(min>(256-zero))
            //{
              //  min=256-zero;
                //  minIndex = i;
                 //   specific_hash_result = hash_result;
           // }
            //std::cout<<"i"<<i<<"score"<<(256-zero)<<" "<<double(randomGenerator())/100000000<<" "<<check_recursive(bucketArray[i][hash_result].oldbitmap,0,128,0)<<std::endl;
            //  if(check_recursive(bucketArray[i][hash_result].oldbitmap,0,128,0)==0
              //||check_recursive(bucketArray[i][hash_result].oldbitmap,0,128,0)==7
             // ||(256-zero)<double(randomGenerator())/100000000)
             // {      minIndex = i;
              //      specific_hash_result = hash_result;

                //      if (std::find(std::begin(real), std::end(real), int_to_ip(bucketArray[i][hash_result].sourceIP)) != std::end(real)) 
                 //       std::cout<<"tihuan"<<int_to_ip(bucketArray[i][hash_result].sourceIP)<<" zero"<<256-zero<<" credit"<<check_recursive(bucketArray[i][hash_result].oldbitmap,0,128,0)<<std::endl;
                  //  break;
                    //std::fill(bucketArray[i][hash_result].bitmap.begin(),bucketArray[i][hash_result].bitmap.end(),false);
           //} 
            //}
 //double zero=std::count(bucketArray[i][hash_result].bitmap.begin(), bucketArray[i][hash_result].bitmap.end(), false);
                  // if(minIndex==65536&&(256-zero)<(double(randomGenerator())/5000000000)){
                  //  minIndex = i;
                   // specific_hash_result = hash_result;
     //}
     //else minIndex=65536;
          // }
 //double zero=std::count(bucketArray[i][specific_hash_result].bitmap.begin(), bucketArray[i][specific_hash_result].bitmap.end(), false);
            int checkche=check_recursive(bucketArray[i][hash_result].oldbitmap,0,128,0);
    // 真正的替换逻辑
//if((std::find(std::begin(real), std::end(real), int_to_ip(bucketArray[i][specific_hash_result].sourceIP)) != std::end(real))){
//std::cout<<"kik"<<(256-zero)<<" rand"<<(double(randomGenerator())/300000000)<<" cheng"<<checkche<<" count"<<bucketArray[i][specific_hash_result].count<<std::endl;
//}
    
    if(//!(std::find(std::begin(real), std::end(real), int_to_ip(bucketArray[i][specific_hash_result].sourceIP)) != std::end(real)) &&
    (bucketArray[i][hash_result].count/(bitmapSize-zero)>3&&(bitmapSize-zero)<(double(randomGenerator())/300000000))||checkche==0||checkche==128){
       // std::cout<<"tihuan"<<"i="<<int_to_ip( bucketArray[minIndex][specific_hash_result].sourceIP)<<" "<<zero<<" "<<zero1<<" "<<hash_result<<std::endl;
                //Bucket::bucket new_bucket(src, bitmapSize, 0);
                 //std::cout<<"src"<<int_to_ip(bucketArray[i][hash_result].sourceIP)
                 //<<" new src"<<int_to_ip(src)<<" jis"<<(256-zero)<<" "<<bucketArray[i][hash_result].count/(256-zero)/(256-zero)<<" rand"<<(double(randomGenerator())/300000000)<<" cheng"<<checkche<<std::endl;
   
                bucketArray[i][hash_result].sourceIP=0;
                
                //bucketArray[minIndex][specific_hash_result].sourceIP =0;
                bucketArray[i][hash_result].count=0;
                operate_bucket = &bucketArray[i][hash_result];
        std::fill(operate_bucket->oldbitmap.begin(),operate_bucket->oldbitmap.end(),false);
        std::fill(operate_bucket->bitmap.begin(),operate_bucket->bitmap.end(),false);
        break;
          //     std::cout<<"tihuan"<<int_to_ip(operate_bucket->sourceIP)<<" zero"<<256-zero<<std::endl;
                  //  
                //std::cout<<"tihuanle"<<minIndex<<" "<<specific_hash_result<<std::endl;
    }}}
        //（2）桶内对目的IP进行分段哈希
        int left = 0; // 左边界
        int right = 128;//bitmapSize; // 右边界
        uint32_t mask = (1 << group) - 1; // 逻辑与的mask
        int segment_hash_result; // 分段哈希的结果
        int oot=0;
        uint8_t kio=0;
        if (operate_bucket != nullptr) {
                // 选右（左侧不纳入哈希范围）
            
    int left_prefix = 0, right_prefix = 128;
    uint32_t dt=dst>>(32-group);
       int midf=group;
       int mid_prefix = (left_prefix + right_prefix) / 2;
    while (left_prefix < right_prefix-1) {
            mid_prefix = (left_prefix + right_prefix) / 2;
           uint64_t hash_result = (Hash::BOBHash64((uint8_t*)&dt, sizeof(u_int64_t), BFSEED));
            if(hash_result%2)
            right_prefix = mid_prefix;
            else left_prefix = mid_prefix;
       
            if (hash_result % 2)
                    right_prefix = mid_prefix; // drill 左边
            else
                    left_prefix = mid_prefix;  // drill 右边
            midf+=group;
            dt=dst >> (32-midf);
            }
            //std::cout<<"mid"<<mid_prefix<<"left"<<left_prefix<<"right"<<right_prefix<<" "<<dt<<std::endl;
            operate_bucket->oldbitmap[mid_prefix]=true;
            int hj=check_recursive(operate_bucket->oldbitmap,0,128,0);
            if(hj==0){
            //std::cout<<"hj"<<hj<<" "<<midf<<std::endl;
            operate_bucket->sourceIP=0;
            //std::fill(operate_bucket->bitmap.begin(),operate_bucket->bitmap.end(),false);
            std::fill(operate_bucket->bitmap.begin(),operate_bucket->bitmap.end(),false);
            std::fill(operate_bucket->oldbitmap.begin(),operate_bucket->oldbitmap.end(),false);
            int coumt=std::count(operate_bucket->bitmap.begin(),operate_bucket->bitmap.end(),true);
            //std::cout<<"oko3"<<coumt<<std::endl;
    //if(int_to_ip(operate_bucket->sourceIP)=="4.71.121.40")//51.172.81.7
          //  std::cout<<"1hj"<<hj<<" "<<group*hj<<" "<<midf<<std::endl;
       
            //          if (std::find(std::begin(real), std::end(real), int_to_ip(operate_bucket->sourceIP)) != std::end(real)) 
              //        std::cout<<"chongtu"<<int_to_ip(operate_bucket->sourceIP)<<std::endl;
            }
            else{
        uint64_t cut=dst;//<<(32-group*hj);
        uint32_t finalh = (Hash::BOBHash64((uint8_t*)&cut, sizeof(u_int64_t), BFSEED))%bitmapSize;//hash1(group_bits);
        //std::cout<<"src"<<int_to_ip(src)<<"dst"<<dst<<"mind"<<mid_prefix<<std::endl;
          // if(int_to_ip(operate_bucket->sourceIP)=="4.71.121.40"){//51.172.81.7
            //std::cout<<"hj"<<hj<<" "<<group*hj<<" "<<midf<<std::endl;
        //std::cout<<"cu"<<cut<<" dst"<<dst<<" "<<finalh<<std::endl;}
        operate_bucket->bitmap[finalh] = true;
        //operate_bucket->sourceIP=src;
            }
        }
    }
     auto end = std::chrono::high_resolution_clock::now();
            
        auto duration_s = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cerr << "执行时间: " << double(cooun)/double(duration_s.count()) << " 秒\n";
  
    // 4.统计指标
    double tp, fp, fn;
    double precision, recall;

    // 5.统计结果
    int total=0;
    uint32_t srccc=0;
    int floa=0;
    double are=0;
    double che=0;
    for (int i = 0; i < rowSize; ++i) {
        for (int j = 0; j < colSize; ++j) {
            // 使用阈值筛选结果      
            double zero=std::count(bucketArray[i][j].bitmap.begin(), bucketArray[i][j].bitmap.end(), false);
        
            srccc=bucketArray[i][j].sourceIP;
            //std::cout<<"tihuan"<<"i="<<i<<" "<<zero<<" "<<zero1<<" "<<hash_result<<std::endl;
            double total=bucketArray[i][j].bitmap.size()*std::log(float(bucketArray[i][j].bitmap.size())/float(zero));
            
            double score=float(total)*float(std::log(total+2));///float(1 << (32-4*1));
             int cheng=0;
            if(std::count(bucketArray[i][j].oldbitmap.begin(),bucketArray[i][j].oldbitmap.end(),true)!=0)
                cheng=check_recursive(bucketArray[i][j].oldbitmap,0,128,0);
            int er=1;
           // std::cout<<"df"<<cheng<<std::endl;
            for(int oi=0;oi<32-(group*(cheng+1));oi++)
            er*=2;
//std::cout<<"down"<<int_to_ip(srccc)<<"score"<<score<<"zero"<<bitmapSize-zero<<"er"<<cheng<<" "<<double(score)/double(er)<<std::endl;

if(bucketArray[i][j].sourceIP!=0&&cheng!=0&&cheng!=5&&double(bitmapSize-zero)>120){//&&cheng!=0&&cheng!=7

total++;
//if(check_recursive(bucketArray[i][j].oldbitmap,0,128,0)==0)
std::cout<<"super"<<int_to_ip(srccc)<<"score"<<score<<"zero"<<bitmapSize-zero<<"er"<<cheng<<" "<<double(score)/double(er)<<std::endl;

//int_to_ip(srccc)=="132.142.10.1"||
if(int_to_ip(srccc)=="120.45.67.89")floa=1;
else if(int_to_ip(srccc)=="48.20.240.5")floa=2;
else if(int_to_ip(srccc)=="100.0.0.1")floa=3;
else if(int_to_ip(srccc)=="192.168.200.25")floa=4;
else if(int_to_ip(srccc)=="207.56.89.12")floa=5;
else if(int_to_ip(srccc)=="9.12.45.87")floa=6;
else if(int_to_ip(srccc)=="79.50.23.15")floa=7;
else if(int_to_ip(srccc)=="150.128.34.56")floa=8;
else if(int_to_ip(srccc)=="180.64.150.30")floa=9;
else if(int_to_ip(srccc)=="66.66.123.222")floa=10;
else if(int_to_ip(srccc)=="1.2.3.4")floa=11;
else if(int_to_ip(srccc)=="90.127.254.13")floa=12;
else if(int_to_ip(srccc)=="198.51.100.203")floa=13;
else if(int_to_ip(srccc)=="230.100.3.45")floa=14;
else if(int_to_ip(srccc)=="23.100.88.99")floa=15;
else if(int_to_ip(srccc)=="121.0.113.45")floa=16;
else if(int_to_ip(srccc)=="84.6.8.200")floa=17;
else if(int_to_ip(srccc)=="237.63.111.111")floa=18;
else if(int_to_ip(srccc)=="180.64.150.30")floa=19;
else if(int_to_ip(srccc)=="123.45.67.89")floa=20;
//else floa=0;


if(int_to_ip(srccc)=="82.98.255.33")floa=4;
else if(int_to_ip(srccc)=="43.90.110.9")floa=6;
else if(int_to_ip(srccc)=="47.247.197.194")floa=8;
else if(int_to_ip(srccc)=="14.10.11.219")floa=10;
else if(int_to_ip(srccc)=="8.68.194.246")floa=12;
else if(int_to_ip(srccc)=="174.97.27.49")floa=14;
else if(int_to_ip(srccc)=="54.163.145.8")floa=16;
else if(int_to_ip(srccc)=="187.2.27.144")floa=18;
else if(int_to_ip(srccc)=="188.28.61.164")floa=20;
else if(int_to_ip(srccc)=="8.52.110.122")floa=22;
else if(int_to_ip(srccc)=="200.233.140.100")floa=24;
else if(int_to_ip(srccc)=="205.155.210.84")floa=4;
else if(int_to_ip(srccc)=="68.100.27.118")floa=6;
else if(int_to_ip(srccc)=="108.2.148.61")floa=8;
else if(int_to_ip(srccc)=="51.11.76.231")floa=10;
else if(int_to_ip(srccc)=="164.57.249.195")floa=12;
else if(int_to_ip(srccc)=="102.58.19.90")floa=14;
else if(int_to_ip(srccc)=="122.61.235.72")floa=16;
else if(int_to_ip(srccc)=="94.228.10.51")floa=18;
else if(int_to_ip(srccc)=="168.243.56.16")floa=20;
else if(int_to_ip(srccc)=="6.78.188.160")floa=22;
else if(int_to_ip(srccc)=="6.69.227.10")floa=24;
else if(int_to_ip(srccc)=="153.172.111.153")floa=4;
else if(int_to_ip(srccc)=="4.71.121.40")floa=6;
else if(int_to_ip(srccc)=="18.103.253.18")floa=8;
else if(int_to_ip(srccc)=="215.179.106.14")floa=10;
else if(int_to_ip(srccc)=="150.24.185.117")floa=12;
else if(int_to_ip(srccc)=="164.48.124.233")floa=14;

//else if(int_to_ip(srccc)=="192.13.86.0")floa=16;
//else if(int_to_ip(srccc)=="45.123.10.149")floa=18;
//else if(int_to_ip(srccc)=="192.13.95.195")floa=20;
//else if(int_to_ip(srccc)=="151.157.184.2")floa=22;
//else if(int_to_ip(srccc)=="192.13.85.197")floa=24;
//else if(int_to_ip(srccc)=="80.82.117.247")floa=4;
//else if(int_to_ip(srccc)=="45.123.10.92")floa=6;
//else if(int_to_ip(srccc)=="94.169.208.199")floa=8;
//else if(int_to_ip(srccc)=="192.13.83.190")floa=10;
//else if(int_to_ip(srccc)=="45.123.10.189")floa=12;
//else if(int_to_ip(srccc)=="192.13.83.190")floa=14;
//else if(int_to_ip(srccc)=="192.13.83.191")floa=16;

else if(int_to_ip(srccc)=="21.146.112.3")floa=16;
else if(int_to_ip(srccc)=="176.119.41.86")floa=18;
else if(int_to_ip(srccc)=="44.192.36.20")floa=20;
else if(int_to_ip(srccc)=="166.35.183.195")floa=22;
else if(int_to_ip(srccc)=="88.36.49.157")floa=24;
else if(int_to_ip(srccc)=="51.172.81.7")floa=4;
else if(int_to_ip(srccc)=="47.255.92.140")floa=6;
else if(int_to_ip(srccc)=="127.82.222.232")floa=8;
else if(int_to_ip(srccc)=="31.204.192.2")floa=10;
else if(int_to_ip(srccc)=="101.167.51.236")floa=12;
else if(int_to_ip(srccc)=="179.245.215.236")floa=14;
else if(int_to_ip(srccc)=="91.73.118.25")floa=16;
else if(int_to_ip(srccc)=="182.75.67.47")floa=18;
else if(int_to_ip(srccc)=="106.36.68.194")floa=20;
else if(int_to_ip(srccc)=="74.204.161.89")floa=22;
else if(int_to_ip(srccc)=="152.14.104.54")floa=24;
else if(int_to_ip(srccc)=="216.170.99.145")floa=4;
else if(int_to_ip(srccc)=="24.68.107.167")floa=6;
else if(int_to_ip(srccc)=="184.139.55.102")floa=8;
else if(int_to_ip(srccc)=="93.132.19.157")floa=10;
else if(int_to_ip(srccc)=="157.250.232.126")floa=12;
else if(int_to_ip(srccc)=="75.195.216.94")floa=14;
else floa=0;
//||int_to_ip(srccc)=="45.19.201.250"
//||int_to_ip(srccc)=="192.13.95.195"
//||int_to_ip(srccc)=="80.82.117.247"
//||int_to_ip(srccc)=="94.169.208.199"
//||int_to_ip(srcc)=="45.111.15.239"
//||int_to_ip(srcc)=="157.221.61.57"
if(floa>0)
{          are+=(200-(bitmapSize-zero));
           che+=(cheng*group-floa);
    std::cout<<"njn"<<int_to_ip(srccc)<<" "<<cheng*group<<"true"<<floa<<std::endl;
         //if(is_first_level_single_sided(bucketArray[i][j].bitmap))
         scount++;}
            else wrcount++;
            //std::cout<<"sIP"<<int_to_ip(srcc)<<"count"<<bucketArray[i][j].hit<<" "<<QueryLC(bucketArray[i][j].bitmap)<<std::endl;
            //std::cout<<is_first_level_single_sided(bucketArray[i][j].bitmap)<<std::endl;
            }
            //else //if(Bucket::CalculateSkewness(operate_bucket->bitmap)<18)
            //wrcount++;
          

                //std::cout << "i: " << i << ", j: " << j << ", " << bucketArray[i][j].sourceIP << ", " << bucketArray[i][j].count << "\n";
                // 实际为攻击流，结果为攻击流
                 // if(bucketArray[i][j].hit>1000){
            //if(QueryLC(bucketArray[i][j].bitmap)>threshold){
            //std::cout<<"IP"<<bucketArray[i][j].sourceIP<<std::endl;
            //std::cout<<"Hit"<<bucketArray[i][j].hit<<" "<<QueryLC(bucketArray[i][j].bitmap)<<std::endl;
           
              //  if (std::find(std::begin(real), std::end(real), int_to_ip(bucketArray[i][j].sourceIP)) != std::end(real)) {
                //    tp += 1;
                // 实际为正常流，结果为攻击流
                //} else {
                  //  fp += 1;
                //}
            //}
            
            //}
        }
    }


   for(string itt:real) 
    for (int i = 0; i < rowSize; ++i) {
        for (int j = 0; j < colSize; ++j) {

if(bucketArray[i][j].count==1){
uint32_t srcct=bucketArray[i][j].sourceIP;
//std::cout<<"njn"<<int_to_ip(srcc)<<std::endl;
      if(itt==int_to_ip(srcct))tp++;break;}

        }}
    // 实际为攻击流，但结果为正常流的源IP数量
    fn = 50 - tp;
  sxcount=50 - scount;
    fp=50-tp;
    // 6.输出结果
    precision = tp / (tp + fp);
    recall = tp / (tp + fn);
    std::cout << "tp: " << tp << ", fp: " << fp << ", fn: " << fn << "\n";
    std::cout << "[Result] Precision: " << precision << "\n[Result] Recall: " << recall << "\n";
std::cout<<"scount"<<scount<<"wrcount"<<wrcount<<"sx"<<sxcount<<std::endl;
double recalll=double(scount)/double(sxcount+scount);
double precision1=double(scount)/double(wrcount+scount);
double de=(2*precision1*recalll)/double(precision1+recalll);
std::cout<<"recall"<<recalll;
std::cout<<"precision"<<precision1;
std::cout<<"f1"<<de;
std::cout<<"vheng"<<double(che)/double(sxcount)<<std::endl;
std::cout<<"are"<<are/scount/200;
std::cout<<"total"<<total;
//std::cout<<"f1"<<(2*precision*real)/double(precision+real);
    return 0;
}