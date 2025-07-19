#include "utils.h"
#include "queue.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "debug.h"
#include "action.h"
//释放vpndata内存空间
bool FreeConnVPNDataMem(VpnData *vpndata)
{
    check_and_free(vpndata->ip);
    check_and_free(vpndata->username);
    for(int i=0;i<vpndata->group_len;i++){
        check_and_free(vpndata->groups[i].groupname);
        check_and_free(vpndata->groups[i].description);
    }
    vpndata->group_len=0;
    check_and_free(vpndata->groups);
    check_and_free(vpndata);
    return true;
}
//初始化队列
bool InitConnVpnQueue(ConnQueue **CQ){
    (*CQ)=malloc(sizeof(ConnQueue));
    if(NULL==CQ) return false;
    ConnNode *pConnNode=(ConnNode *)malloc(sizeof(ConnNode));
    if(NULL==pConnNode) return false;
    (*CQ)->front=(*CQ)->rear=pConnNode;
    (*CQ)->front->next=NULL;
    (*CQ)->len=0;
    return true;
}
// 销毁队列
bool DestroyVpnQueue(ConnQueue *CQ){
    if(!CQ) return false;
    ConnNode *t=CQ->front->next;
    CQ->len=0;
    while(t){
        FreeConnVPNDataMem(t->data);
        check_and_free(t);
        t=t->next;
    }
    check_and_free(CQ->front);
    check_and_free(CQ);
    return true;
}
//判断队列里是否存在
bool ExistVpnQueue(ConnQueue *CQ,VpnData *value){
    if(!CQ->front) return false;
    ConnNode *t=CQ->front->next;
    while(t)
    {
        // 以IP作为唯一标识
        if(!strcmp(t->data->ip,value->ip) /* && !strcmp(t->data->username,username) */ )
            return true;
        else
            t=t->next;
    }
    return false;
}
//加入到队列尾
bool JoinVpnQueue(ConnQueue *CQ,VpnData *value){
    if (ExistVpnQueue(CQ,value)) 
    {
        LOGWARNING("already have ip value [%s].not add queue.",value->ip);
        FreeConnVPNDataMem(value);
        return false;
    }
    ConnNode *p = (ConnNode *)malloc(sizeof(ConnNode));
    p->data=value;
    p->next=NULL;
    CQ->rear->next=p;
    CQ->rear=p;
    CQ->len++;
    return true;
}
//加入到队列前
bool JoinBeforeVpnQueue(ConnQueue *CQ,VpnData *value){
    if (ExistVpnQueue(CQ,value)) 
    {
        LOGWARNING("already have ip value [%s].",value->ip);
        return false;
    }
    ConnNode *p = (ConnNode *)malloc(sizeof(ConnNode));
    p->data=value;
    p->next=CQ->front->next;
    CQ->front->next=p;
    CQ->len++;
    return true;
}
//更新队列
bool UpdateOrJoinVpnQueue(ConnQueue *CQ,VpnData *value){
    ConnNode *t=CQ->front->next;
    // 遍历队列，如果有重复，就更新，没有就在队列尾添加。
    while(t)
    {
        if(!strcmp(t->data->ip,value->ip) /* && !strcmp(t->data->username,username) */ )
        {   
            check_and_free(t->data);
            t->data=value;
            return true;
        }
        else
            t=t->next;
    }
    ConnNode *p = (ConnNode *)malloc(sizeof(ConnNode));
    p->data=value;
    p->next=NULL;
    CQ->rear->next=p;
    CQ->rear=p;
    CQ->len++;
    return true;
}
//从队列前面取出队列
bool LeaveVpnQueue(ConnQueue *CQ,VpnData **returndata){
    if(CQ->front==CQ->rear) return false;
    ConnNode *p=CQ->front->next;
    (*returndata)=p->data;
    CQ->front->next=p->next;
    if(p->next==NULL) CQ->rear=CQ->front;
    CQ->len--;
    check_and_free(p);
    return true;
}
//按IP值取出队列项
bool ByValueLeaveVpnQueue(ConnQueue *CQ, char *ip, VpnData **returndata)
{
    if(!ip) return false;
    if(CQ->front==CQ->rear) return false;
    ConnNode *tmp = CQ->front->next;
    ConnNode *predata=NULL;
    while(tmp)
    {
        if (!strcmp(tmp->data->ip, ip)) 
        {
            (*returndata)=tmp->data;
            if(predata==NULL) //如果在队列首
            {
                if(tmp->next==NULL) //如果只一条
                {
                    CQ->front=CQ->rear=(ConnNode *)malloc(sizeof(ConnNode));
                    CQ->front->next=NULL;
                    CQ->len--;
                    return 1;
                }
                else
                   CQ->front->next=tmp->next;
            }
            else if(tmp->next==NULL){ //如果在队列结尾
                predata->next=NULL;
                CQ->rear=predata;
            }else{ //在队列中
                 predata->next=tmp->next;
            }
            CQ->len--;
            check_and_free(tmp);
            return true;
        }
        else
        {
            predata=tmp;
            tmp = tmp->next;
        }
    }
    return false;
}
//队列元素个数
int getVpnQueueLength(ConnQueue *CQ){
    // int length=0;
    // ConnNode *p=CQ->front;
    // while(p!=CQ->rear){
    //     p=p->next;
    //     length++;
    // }
    return CQ->len;
}