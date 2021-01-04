#include <stdbool.h>

typedef struct Vpn_Conn_Groups_t 
{
    char  *groupname;
    char  *description;
}VpnConnGroups;

// 保存连接信息
typedef struct VpnData_s
{
    char *ip;
    char *username;
    int  group_len;
    VpnConnGroups *groups;
}VpnData;

typedef struct ConnNode_s{
    VpnData *data;
    struct ConnNode_s *next;
}ConnNode;

typedef struct ConnQueue_s{
    ConnNode *front;
    ConnNode *rear;
    unsigned int len;
}ConnQueue;

// 定义全局队列
ConnQueue *ConnVpnQueue_r;
// dbh888 extra 2019-08-23

extern bool InitConnVpnQueue(ConnQueue **CQ);
//释放vpndata内存空间
bool FreeConnVPNDataMem(VpnData *vpndata);
// 销毁队列
extern bool DestroyVpnQueue(ConnQueue *CQ);
//判断队列里是否存在
extern bool ExistVpnQueue(ConnQueue *CQ,VpnData *value);
//加入到队列尾
extern bool JoinVpnQueue(ConnQueue *CQ,VpnData *value);
//加入到队列前
extern bool JoinBeforeVpnQueue(ConnQueue *CQ,VpnData *value);
//更新队列
extern bool UpdateOrJoinVpnQueue(ConnQueue *CQ,VpnData *value);
//从队列前面取出队列
extern bool LeaveVpnQueue(ConnQueue *CQ,VpnData **returndata);
//按IP值取出队列项
extern bool ByValueLeaveVpnQueue(ConnQueue *CQ, char *ip, VpnData **returndata);
//队列元素个数
extern int getVpnQueueLength(ConnQueue *CQ);