#include "queue.h"
#include "debug.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "debug.h"

//初始化队列
bool InitConnVpnQueue(ConnQueue **CQ){
    (*CQ)=malloc(sizeof(ConnQueue));
    if(NULL==CQ) return false;
    ConnNode *pConnNode=(ConnNode *)malloc(sizeof(ConnNode));
    if(NULL==pConnNode) return false;
    (*CQ)->front=(*CQ)->rear=pConnNode;
    (*CQ)->front->next=NULL;
    return true;
}
// 销毁队列
bool DestroyVpnQueue(ConnQueue *CQ){
    if(!CQ) return false;
    ConnNode *t=CQ->front->next;
    while(t){
        free(t->data);
        free(t);
        t=t->next;
    }
    free(CQ->front);
    free(CQ);
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
        LOGWARNING("already have ip value [%s].",value->ip);
        return false;
    }
    ConnNode *p = (ConnNode *)malloc(sizeof(ConnNode));
    p->data=value;
    p->next=NULL;
    CQ->rear->next=p;
    CQ->rear=p;
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
            free(t->data);
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
    return true;
}
//从队列前面取出队列
bool LeaveVpnQueue(ConnQueue *CQ,VpnData **returndata){
    if(CQ->front==CQ->rear) return false;
    ConnNode *p=CQ->front->next;
    (*returndata)=p->data;
    CQ->front->next=p->next;
    if(p->next==NULL) CQ->rear=CQ->front;
    free(p);
    return true;
}
//按IP值取出队列项
bool ByValueLeaveVpnQueue(ConnQueue *CQ, char *ip, VpnData **returndata)
{
    if(!ip) return false;
    if(CQ->front==CQ->rear) return false;
    LOGINFO("test");
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
            free(tmp);
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
    int length=0;
    ConnNode *p=CQ->front;
    while(p!=CQ->rear){
        p=p->next;
        length++;
    }
    return length;
}