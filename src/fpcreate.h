/*
**  $Id$
**
**  fpcreate.h
**
** Copyright (C) 2014-2017 Cisco and/or its affiliates. All rights reserved.
** Copyright (C) 2002-2013 Sourcefire, Inc.
** Dan Roelker <droelker@sourcefire.com>
** Marc Norton <mnorton@sourcefire.com>
**
** NOTES
** 5.7.02 - Initial Sourcecode.  Norton/Roelker
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
** 6/13/05 - marc norton
**   Added plugin support for fast pattern match data
**
*/
#ifndef __FPCREATE_H__
#define __FPCREATE_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rules.h"
#include "treenodes.h"
//#include "parser.h"
#include "pcrm.h"

/*
 *  Max Number of Protocols Supported by Rules in fpcreate.c
 *  for tcp,udp,icmp,ip ... this is an array dimesnion used to
 *  map protocol-ordinals to port_groups ...
 */
/* This is now defined in sftarget_protocol_refererence.h"
 * #define MAX_PROTOCOL_ORDINAL 8192 */
#include "sftarget_protocol_reference.h"


/*
 *  This controls how many fast pattern match contents may be
 *  used/retrieved per rule in fpcreate.c.
 */
#define PLUGIN_MAX_FPLIST_SIZE 16

#define PL_BLEEDOVER_WARNINGS_ENABLED        0x01
#define PL_DEBUG_PRINT_NC_DETECT_RULES       0x02
#define PL_DEBUG_PRINT_RULEGROWP_BUILD       0x04
#define PL_DEBUG_PRINT_RULEGROUPS_UNCOMPILED 0x08
#define PL_DEBUG_PRINT_RULEGROUPS_COMPILED   0x10
#define PL_SINGLE_RULE_GROUP                 0x20

typedef struct _pmx_
{

   void * RuleNode;
   void * PatternMatchData;

} PMX;

/* Used for negative content list */
typedef struct _NCListNode
{
    PMX *pmx;
    struct _NCListNode *next;

} NCListNode;

/*
**  This structure holds configuration options for the
**  detection engine.
*/
typedef struct _FastPatternConfig
{
    int inspect_stream_insert; //进行流插入时数据包不被引擎评估
    int search_method; //模式匹配方法
    int search_opt;	//是否进行优化搜索的标志位
    int search_method_verbose;
    int debug;
    unsigned int max_queue_events;//一次可以命中的模式串数量 默认5条
    unsigned int bleedover_port_limit;//当规则中的源端口或者目的端口最大达到多少是将会考虑将其加入到any-any端口组中 默认1024
    int configured;
    int portlists_flags;  //端口列表标志位
    int split_any_any;
	/*split_any_any 标志是内存和性能的权衡，默认情况下any-any端口规则被添加到每个
	非any-any端口组中使得每个包仅被一个端口组规则评估。在没有很多any-any端口规则的情况下，如果不把any-any端口规则添加到每个其他的端口规则组中,可以有效减少模式匹配
	所带来的内存占用的开销，但是这样做的话每个包就需要进行来个端口组的评估(一个是指定的端口组一个是any-any端口组)因此会比较明显的降低性能
	这个选项是通用的可以被任何搜索算法使用，尽管专门用于模式匹配的ac算法整体快速模式性能优于ac-bnfa，但内存占用量会显着减少。需要注意的将低的内存占用由于由较低的cache miss，
	也会带来性能的提升*/
    int max_pattern_len; //匹配模式长度
    int num_patterns_truncated;  /* due to max_pattern_len */
    int num_patterns_trimmed;    /* due to zero byte prefix */
    int debug_print_fast_pattern;

} FastPatternConfig;

#ifdef TARGET_BASED
/*
 *  Service Rule Map Master Table
 */
typedef struct
{
  SFGHASH * tcp_to_srv;
  SFGHASH * tcp_to_cli;

  SFGHASH * udp_to_srv;
  SFGHASH * udp_to_cli;

  SFGHASH * icmp_to_srv;
  SFGHASH * icmp_to_cli;

  SFGHASH * ip_to_srv;
  SFGHASH * ip_to_cli;

} srmm_table_t;

/*
 *  Service/Protocol Oridinal To PORT_GROUP table
 */
typedef struct
{
  PORT_GROUP *tcp_to_srv[MAX_PROTOCOL_ORDINAL];
  PORT_GROUP *tcp_to_cli[MAX_PROTOCOL_ORDINAL];

  PORT_GROUP *udp_to_srv[MAX_PROTOCOL_ORDINAL];
  PORT_GROUP *udp_to_cli[MAX_PROTOCOL_ORDINAL];

  PORT_GROUP *icmp_to_srv[MAX_PROTOCOL_ORDINAL];
  PORT_GROUP *icmp_to_cli[MAX_PROTOCOL_ORDINAL];

  PORT_GROUP *ip_to_srv[MAX_PROTOCOL_ORDINAL];
  PORT_GROUP *ip_to_cli[MAX_PROTOCOL_ORDINAL];

} sopg_table_t;
#endif

/*
**  This function initializes the detection engine configuration
**  options before setting them.
*/
int fpInitDetectionEngine(void);

/*
**  This is the main routine to create a FastPacket inspection
**  engine.  It reads in the snort list of RTNs and OTNs and
**  assigns them to PORT_MAPS.
*/
int fpCreateFastPacketDetection(struct _SnortConfig *);

FastPatternConfig * FastPatternConfigNew(void);
void fpSetDefaults(FastPatternConfig *);
void FastPatternConfigFree(FastPatternConfig *);

/*
**  Functions that allow the detection routins to
**  find the right classification for a given packet.
*/
int prmFindRuleGroupIp(PORT_RULE_MAP *, int, PORT_GROUP **, PORT_GROUP **);
int prmFindRuleGroupIcmp(PORT_RULE_MAP *, int, PORT_GROUP **, PORT_GROUP **);

#ifdef TARGET_BASED
int prmFindRuleGroupTcp(PORT_RULE_MAP *prm, int dport, int sport, PORT_GROUP ** src, PORT_GROUP **dst, PORT_GROUP **nssrc, PORT_GROUP **nsdst, PORT_GROUP ** gen);
int prmFindRuleGroupUdp(PORT_RULE_MAP *prm, int dport, int sport, PORT_GROUP ** src, PORT_GROUP ** dst, PORT_GROUP **nssrc, PORT_GROUP **nsdst, PORT_GROUP ** gen);
#else
int prmFindRuleGroupTcp(PORT_RULE_MAP *, int, int, PORT_GROUP **, PORT_GROUP **, PORT_GROUP **);
int prmFindRuleGroupUdp(PORT_RULE_MAP *, int, int, PORT_GROUP **, PORT_GROUP **, PORT_GROUP **);
#endif

int fpSetDetectSearchMethod(FastPatternConfig *, char *);
void fpSetDetectSearchOpt(FastPatternConfig *, int flag);
void fpSetDebugMode(FastPatternConfig *);
void fpSetStreamInsert(FastPatternConfig *);
void fpSetMaxQueueEvents(FastPatternConfig *, unsigned int);
void fpDetectSetSplitAnyAny(FastPatternConfig *, int);
void fpSetMaxPatternLen(FastPatternConfig *, unsigned int);

void fpDetectSetSingleRuleGroup(FastPatternConfig *);
void fpDetectSetBleedOverPortLimit(FastPatternConfig *, unsigned int);
void fpDetectSetBleedOverWarnings(FastPatternConfig *);
void fpDetectSetDebugPrintNcRules(FastPatternConfig *);
void fpDetectSetDebugPrintRuleGroupBuildDetails(FastPatternConfig *);
void fpDetectSetDebugPrintRuleGroupsCompiled(FastPatternConfig *);
void fpDetectSetDebugPrintRuleGroupsUnCompiled(FastPatternConfig *);
void fpDetectSetDebugPrintFastPatterns(FastPatternConfig *, int);

int  fpDetectGetSingleRuleGroup(FastPatternConfig *);
int  fpDetectGetBleedOverPortLimit(FastPatternConfig *);
int  fpDetectGetBleedOverWarnings(FastPatternConfig *);
int  fpDetectGetDebugPrintNcRules(FastPatternConfig *);
int  fpDetectGetDebugPrintRuleGroupBuildDetails(FastPatternConfig *);
int  fpDetectGetDebugPrintRuleGroupsCompiled(FastPatternConfig *);
int  fpDetectGetDebugPrintRuleGroupsUnCompiled(FastPatternConfig *);
int  fpDetectSplitAnyAny(FastPatternConfig *);
int  fpDetectGetDebugPrintFastPatterns(FastPatternConfig *);

void fpDeleteFastPacketDetection(struct _SnortConfig *);
void free_detection_option_tree(detection_option_tree_node_t *node);

int OtnFlowDir( OptTreeNode * p );
#ifdef TARGET_BASED
PORT_GROUP * fpGetServicePortGroupByOrdinal(sopg_table_t *, int, int, int16_t);
#endif

/*
**  Shows the event stats for the created FastPacketDetection
*/
void fpShowEventStats(struct _SnortConfig *);
typedef int (*OtnWalkFcn)(int, RuleTreeNode *, OptTreeNode *);
void fpWalkOtns(int, OtnWalkFcn);
void fpDynamicDataFree(void *);

const char * PatternRawToContent(const char *pattern, int pattern_len);

#endif  /* __FPCREATE_H__ */
