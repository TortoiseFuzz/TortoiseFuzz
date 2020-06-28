/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../../config.h"
#include "../../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/DebugInfo.h"

#include "llvm/IR/CFG.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/GraphWriter.h"

#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Pass.h"
#include "llvm/Support/FileSystem.h"

#include "llvm/ADT/SCCIterator.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
// #include "llvm/Analysis/LoopInfo.h"

using namespace llvm;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

typedef struct ArcNode{
  int adjvex;
  struct ArcNode *nextarc;
}ArcNode;
#define MAX_VERTEX_NUM 35536
typedef struct VNode{
  std::string bb_name;
  unsigned int cur_loc;
  int outdegree;
  int indegree;
  bool visited;
  unsigned int loop_stat; //0: undetected, 1: in detection prog, 2: all succ_bb detected 
  unsigned int loop_cnt;
  int loop_pre_bb_num[10];
  ArcNode *firarc;
}VNode, AdjList[MAX_VERTEX_NUM];

typedef struct ALGraph{
  int vexnum;
  int arcnum;
  AdjList list;
}ALGraph;

int search_vnode(ALGraph *cfg, std::string bb_name){
  for(int i = 0; i < cfg->vexnum; i++){
    if(cfg->list[i].bb_name == bb_name)
      return i;
  }
  return -1;
}

int insert_vnode(ALGraph *cfg, std::string bb_name){
  //find existing vnode
  int bb_num = search_vnode(cfg, bb_name);
  if(bb_num != -1)
    return bb_num;
  //create vnode
  bb_num = cfg->vexnum++;
  if(bb_num >= MAX_VERTEX_NUM){
    errs() << "too many nodes\n";
    exit(-1);
  }
  cfg->list[bb_num].bb_name = bb_name;
  cfg->list[bb_num].cur_loc = AFL_R(MAP_SIZE);
  cfg->list[bb_num].firarc = NULL;
  cfg->list[bb_num].indegree = 0;
  cfg->list[bb_num].outdegree = 0;
  cfg->list[bb_num].visited = false;
  cfg->list[bb_num].loop_stat = 0;
  cfg->list[bb_num].loop_cnt = 0;
  return bb_num;
}

bool insert_edge(ALGraph *cfg, int bb_num, int suc_bb_num){
  ArcNode *arc;
  ArcNode *temp, *ins_loc;
  arc = (ArcNode *)malloc(sizeof(ArcNode));
  arc->adjvex = suc_bb_num;
  arc->nextarc = NULL;

  temp = cfg->list[bb_num].firarc;
  cfg->arcnum++;
  cfg->list[bb_num].outdegree++;
  cfg->list[suc_bb_num].indegree++;
  
  if(temp == NULL){
    cfg->list[bb_num].firarc = arc;
    return true;
  }

  //here remove replicate next bb
  for(; temp != NULL; temp = temp->nextarc){
    if(temp->adjvex == suc_bb_num){
      free(arc);
      cfg->arcnum--;
      cfg->list[bb_num].outdegree--;
      cfg->list[suc_bb_num].indegree--;
      return false;
    }
    ins_loc = temp;
  }

  ins_loc->nextarc = arc;
  return true;
}

void _loop_detect(ALGraph *cfg, ArcNode *an, int pre_bb_num){
  VNode *vn;
  vn = &(cfg->list[an->adjvex]);

  if(vn->outdegree == 0 || vn->loop_stat == 2){ // no out edge
    return ;
  }

  if(vn->loop_stat == 1){ // is loop 
    vn->loop_pre_bb_num[vn->loop_cnt++] = pre_bb_num;
    return ;
  }
  
  //update the flag to say it's in the loop detecting process
  if(vn->loop_stat == 0)
    vn->loop_stat = 1;
  

  ArcNode *temp;
  for(temp = vn->firarc; temp != NULL; temp = temp->nextarc){
    _loop_detect(cfg, temp, an->adjvex);
  }
  //detecting complete
  vn->loop_stat = 2;
}

//DFS again
void loop_detect(ALGraph *cfg){
  if(cfg->vexnum == 0)
    return ;

  ArcNode *temp;

  for(temp = cfg->list[0].firarc; temp != NULL; temp = temp->nextarc){
    _loop_detect(cfg, temp, 0);
    VNode *vn;
    vn = &(cfg->list[temp->adjvex]);
    vn->loop_stat = 2;
  }
}

std::string bb_getname(BasicBlock *bb){
  std::string bb_name;
  bb_name = bb->getName();

  if(bb_name.empty()){
    std::string Str;
    raw_string_ostream OS(Str);
    bb->printAsOperand(OS, false);
    std::string func_name = bb->getParent()->getName();
    bb_name = func_name + OS.str();
    bb->setName(bb_name);
    // outs() << OS.str() << "\n";
  }

  return bb_name;
}

char AFLCoverage::ID = 0;


bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. Note that
     __afl_prev_loc is thread-local. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  GlobalVariable *AFLLoopPtr = 
      new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                        GlobalValue::ExternalLinkage, 0, "__afl_loop_ptr");
  
  GlobalVariable *AFLPrevLoc = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
      0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

  /* Instrument all the things! */

  int inst_blocks = 0;
  
  std::string module_name = M.getName();

  char *oldname, *p, *tempp;
  oldname = new char [module_name.size() + 1];
  strcpy(oldname, module_name.c_str());
  p = strtok(oldname, "/");
  while(p != NULL){
    tempp = p;
    p=strtok(NULL,"/");
  }
  module_name = tempp;
  delete[] oldname;


  // outs() << "Module name: " << module_name << "\n";
  for (auto &F : M){
    std::string func_name = F.getName();
    // outs() << "Func name: " << func_name << "\n";
    ALGraph cfg;
    // memset(&cfg, 0, sizeof(ALGraph));
    cfg.arcnum = 0;
    cfg.vexnum = 0;
    int bb_num = 0;

    for (auto &BB : F){
      std::string bb_name = bb_getname(&BB);
      // outs() << "\nbb name: " << bb_name << "\n";
      bb_num = insert_vnode(&cfg, bb_name);

      //build CFG
      for (succ_iterator PI = succ_begin(&BB), E = succ_end(&BB); PI != E; ++PI) {
        BasicBlock *SuccBB = *PI;
        std::string suc_bb_name = bb_getname(SuccBB);
        int suc_bb_num = insert_vnode(&cfg, suc_bb_name);        
        insert_edge(&cfg, bb_num, suc_bb_num);
      }
    }

    loop_detect(&cfg);
    
    for (auto &BB : F) {
      std::string bb_name = BB.getName();
      // outs() << "BB name: " << bb_name << "\n";
      bb_num = search_vnode(&cfg, bb_name);
      if(bb_num == -1){
        continue;
      }
      // outs() << "BB No." << bb_num << "\n";
      // outs() << "BB size: " << BB.size() << "\n";

      /* Make up cur_loc */
      ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cfg.list[bb_num].cur_loc);

      //if it's a loop back edge, then update loop map
      if(cfg.list[bb_num].loop_cnt > 0){
        // outs() << "add loop in " << cfg.list[bb_num].bb_name << "\n";
        Instruction *fir_ins = &*BB.getFirstInsertionPt();
        IRBuilder<> build(fir_ins);
        TerminatorInst *then_inst;
        LoadInst *PrevLoc = build.CreateLoad(AFLPrevLoc);
        Value *PrevLocCasted = build.CreateZExt(PrevLoc, build.getInt32Ty());
        Value* EdgeId = build.CreateXor(PrevLocCasted, CurLoc);

        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        ConstantInt *Cmp_Prev = ConstantInt::get(Int32Ty, cfg.list[cfg.list[bb_num].loop_pre_bb_num[0]].cur_loc >> 1);
        Value *CmpCond = build.CreateICmp(CmpInst::ICMP_UGT, Cmp_Prev, PrevLoc);
        then_inst = SplitBlockAndInsertIfThen(CmpCond, fir_ins, false);
        build.SetInsertPoint(then_inst);

        LoadInst *LoopPtr = build.CreateLoad(AFLLoopPtr);
        LoopPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *LoopPtrIdx = build.CreateGEP(LoopPtr, EdgeId);

        LoadInst *LoopCounter = build.CreateLoad(LoopPtrIdx);
        LoopCounter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        Value *LoopIncr = build.CreateAdd(LoopCounter, ConstantInt::get(Int32Ty, 1));
        build.CreateStore(LoopIncr, LoopPtrIdx)
            ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      }

      BasicBlock::iterator IP = BB.getFirstInsertionPt();
      IRBuilder<> IRB(&(*IP));

      if (AFL_R(100) >= inst_ratio) continue;

      /* Load prev_loc */

      LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
      PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

      /* Get edge ID as XOR */
      Value* EdgeId = IRB.CreateXor(PrevLocCasted, CurLoc);

      /* Load SHM pointer */

      LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
      MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *MapPtrIdx =
          IRB.CreateGEP(MapPtr, EdgeId);


      LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
      Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
      IRB.CreateStore(Incr, MapPtrIdx)
          ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      
      /* Set prev_loc to cur_loc >> 1 */

      StoreInst *Store =
          IRB.CreateStore(ConstantInt::get(Int32Ty, cfg.list[bb_num].cur_loc >> 1), AFLPrevLoc);
      Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

      inst_blocks++;

    }
  }

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
