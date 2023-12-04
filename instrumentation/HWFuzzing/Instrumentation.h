#pragma once

#include "llvm/Transforms/Instrumentation/SanitizerCoverage.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Optional.h"
#include "llvm/IR/CFG.h"

#include "CoverageMode.h"

#include <cassert>
#include <set>
#include <map>
#include <vector>
#include <string>
#include <random>

namespace {

using namespace llvm;


/// The size of one coverage map element in our coverage map.
static constexpr unsigned MapElementByteSize = 4U;
// Offset in the coverage map in elements of size MapElementByteSize.
typedef unsigned long MapElementOffset;

[[noreturn]]
inline void exitWithErr(std::string error) {
  llvm::errs() << "fatal error: " << error << "\n";
  abort();
}

[[noreturn]]
inline void exitWithErr(std::string error, llvm::Value *v) {
  llvm::errs() << "fatal error: " << error << " - ";
  if (v)
    llvm::errs() << *v;
  else
    llvm::errs() << "nullptr";
  
  llvm::errs() << "\n";
  abort();
}

[[noreturn]]
inline void exitWithErr(std::string error, llvm::Value &v) {
  exitWithErr(error, &v);
}

static unsigned getBytesForType(llvm::Type *type) {
  unsigned bytes = type->getScalarSizeInBits() / 8U;
  if (bytes == 0) return 1;
  return bytes;
}

//-----------------------------------------------------------------------------
// Taint feedback utils.
//-----------------------------------------------------------------------------
static unsigned getBytesForDFSanMemoryOpImpl(llvm::Instruction &i) {
  // Without MSan active, we just need 1 byte for the dfsan label.
  llvm::Function *func = i.getParent()->getParent();
  if (!func->hasFnAttribute(Attribute::SanitizeMemory)) return 1;

  if (auto *load = dyn_cast<LoadInst>(&i))
    return getBytesForType(load->getType());

  if (auto *store = dyn_cast<StoreInst>(&i))
    return getBytesForType(store->getValueOperand()->getType());

  exitWithErr("bits requested for bogus instruction? ", i);
}

static unsigned getBytesForDFSanMemoryOp(llvm::Instruction &i) {
  unsigned bytes = getBytesForDFSanMemoryOpImpl(i);
  if (std::getenv("HWFUZZ_PRINT_SIZES"))
    llvm::errs() << "COVERAGE: Using " << bytes << "B for " << i << "\n";
  return bytes;
}

//-----------------------------------------------------------------------------
// Toggle feedback utils.
//-----------------------------------------------------------------------------
static bool canDoToggleFeedback(llvm::StoreInst &i) {
  return i.getValueOperand()->getType()->isIntegerTy();
}

static unsigned getBytesForToggleOp(llvm::Instruction &i) {
  if (auto *load = dyn_cast<LoadInst>(&i))
    return getBytesForType(load->getType());

  if (auto *store = dyn_cast<StoreInst>(&i))
    return getBytesForType(store->getValueOperand()->getType());

  exitWithErr("bits requested for bogus instruction?", i);
}

static unsigned getSlotsForToggleOp(StoreInst &toggleStore) {
  // Every PCGUARD slot can store 4 bytes, so we need to calculate the
  // number of toggle bits and then return the number of slots we need.
  // Each toggle bit counts for going from 0 to 1 and vice versa, so we
  // twice as many feedback slots.
  const unsigned bytes = getBytesForToggleOp(toggleStore);
  const unsigned slots = (bytes / MapElementByteSize) * 2;
  // We need always at least two slots to store feedback for toggle to 0 and 1.
  if (slots <= 1) return 2;

  return slots;
}

/// Stores information needed to instrument a piece of code with coverage
/// information. Needed because we first scan for coverage points, then
/// allocate the coverage map and then do the actual coverage instrumentation.
struct DelayedInstrumentation {
  MapElementOffset mapPos = 0;

  /// A store/load that provides coverage when it stores/loads tainted data.
  Instruction  *toInstrumentForDFSan = nullptr;

  /// A random instruction at the start of the basic block.
  /// Used for block coverage.
  Instruction  *blockStart = nullptr;

  /// A select that provides coverage depending on which branch it selects.
  SelectInst   *selectInst = nullptr;

  /// A store that provides coverage depending on whether it set each bit
  /// to 0 or 1.
  StoreInst    *toggleStore = nullptr;

  /// A condition brancht hat provides coverade depending on whether it was
  /// taken.
  BranchInst   *branch = nullptr;

  unsigned requiredMapElements() const {
    if (toInstrumentForDFSan) {
      // Every PCGUARD slot can store 4 bytes, so we need to calculate the
      // number of taint bits and then return the number of slots we need.
      const unsigned bytes = getBytesForDFSanMemoryOp(*toInstrumentForDFSan);
      const unsigned slots = bytes / MapElementByteSize;
      // We need always at least one slot to store some feedback.
      if (slots == 0) return 1;
      // More than 4 slots means we have memory op > 128 bits. That's most
      // likely a bug in the size calculation.
      if (slots > 4)
        exitWithErr("Too many dfsan slots. Size calculation wrong?");
      return slots;
    }
    if (selectInst) {
      Type *conditionT = selectInst->getCondition()->getType();
      if (conditionT->isIntegerTy()) return 1;
      return cast<FixedVectorType>(conditionT)->getNumElements();
    }
    if (toggleStore) return getSlotsForToggleOp(*toggleStore);
    // Blocks and branches just need one byte to indicate the status.
    if (branch) return 1;
    if (blockStart) return 1;
    
    exitWithErr("Neither a DFSan, toggle nor select instrumentation?");
  }
};

struct HardwareInstrumentation {
  LLVMContext    *C;
  GlobalVariable *AFLMapPtr = NULL;
  Type           *IntptrTy;
  Type           *IntptrPtrTy;
  Type           *Int64Ty;
  Type           *Int64PtrTy;
  Type           *Int32Ty;
  Type           *Int32PtrTy;
  Type           *Int16Ty;
  Type           *Int8Ty;
  Type           *Int8PtrTy;
  Type           *Int1Ty;
  Type           *Int1PtrTy;
  GlobalVariable **FunctionGuardArray;

  std::vector<DelayedInstrumentation> toInstrument;

  // Bounds check utils to verify that each instrumentation sticks to its own
  // slot in the coverage map. This is just redundant error checking and is
  // not used for anything else.
  MapElementOffset lastMapSize = 0;
  MapElementOffset minAllowedMapAccess = 0;
  MapElementOffset maxAllowedMapAccess = 0;

  void SetNoSanitizeMetadata(Value *V) {
    if (Instruction *I = dyn_cast<Instruction>(V)) SetNoSanitizeMetadata(I);
  }

  void SetNoSanitizeMetadata(Instruction *I) {
    I->setMetadata(I->getModule()->getMDKindID("nosanitize"),
                   MDNode::get(*C, None));
  }

  // DFSan stuff
  bool providesFeedback(const Instruction &inst) {
    // Do not touch code injected by AFL++ itself (which has nosanitize MD).
    // This code never has meaningful taint and just loads AFL++ stuff like
    // the coverage map.
    if (inst.hasMetadata(inst.getModule()->getMDKindID("nosanitize")))
      return false;

    // Optionally mark loads as providing feedback on taint.
    if (isModeOn(CoverageMode::TaintLoads))
      if (isa<LoadInst>(inst)) return true;

    // Optionally mark stores as providing feedback on taint.
    if (isModeOn(CoverageMode::Taint))
      if (isa<StoreInst>(inst)) return true;

    return false;
  }

  enum class MergeTaint { Or, Add };

  void addToCoverageMap(IRBuilder<> &IRB, MapElementOffset mapOffset,
                        Value *coverage, MergeTaint merge_mode) {
    unsigned mapOffsetInBytes = mapOffset * MapElementByteSize;
  
    // Bounds check the map offset.
    if (mapOffset >= lastMapSize)
      exitWithErr("mapOffset beyond lastMapSize (" + std::to_string(mapOffset)
      + " >= " + std::to_string(lastMapSize) + ")");
    if (mapOffset < minAllowedMapAccess)
      exitWithErr("mapOffset below allowed range (" + std::to_string(mapOffset)
      + " < " + std::to_string(minAllowedMapAccess) + ")");
    if (mapOffset >= maxAllowedMapAccess)
      exitWithErr("mapOffset beyond allowed range (" + std::to_string(mapOffset)
      + " >= " + std::to_string(maxAllowedMapAccess) + ")");

    Type *coverage_ptr_type = PointerType::get(coverage->getType(), 0);
    Type *coverage_map_type = Int8Ty;

    if (coverage == nullptr)
      exitWithErr("coverage is a nullptr?");

    if (!coverage->getType()->isIntegerTy())
      exitWithErr("coverage is not an int?");

    // Now load the AFL++ coverage map.
    LoadInst *MapPtr =
        IRB.CreateLoad(PointerType::get(coverage_map_type, 0), AFLMapPtr);
    SetNoSanitizeMetadata(MapPtr);

    // This variable is initialized by AFL++.
    if (*FunctionGuardArray == nullptr)
      exitWithErr("Didn't initialize FunctionGuardArray?");

    // Find the offset in the map we can use to give feedback.
    Value *mapOffset_ptr = ConstantInt::get(IntptrTy, mapOffsetInBytes);
    Value *abs_map_ptr = IRB.CreateAdd(
        IRB.CreatePointerCast(*FunctionGuardArray, IntptrTy), mapOffset_ptr);
    SetNoSanitizeMetadata(abs_map_ptr);

    // Cast that offset to a pointer.
    Value *coverage_counter_ptr = IRB.CreateIntToPtr(abs_map_ptr, Int32PtrTy);
    SetNoSanitizeMetadata(coverage_counter_ptr);

    // Load the old value.
    LoadInst *CurLoc = IRB.CreateLoad(IRB.getInt32Ty(), coverage_counter_ptr);
    SetNoSanitizeMetadata(CurLoc);

    // Load whatever coverage we already got.
    Value *MapPtrIdx = IRB.CreateGEP(coverage_map_type, MapPtr, CurLoc);
    SetNoSanitizeMetadata(MapPtrIdx);

    Value *TypedMapPtrIdx =
        IRB.CreateBitOrPointerCast(MapPtrIdx, coverage_ptr_type);

    LoadInst *Counter =
        IRB.CreateLoad(coverage->getType(), TypedMapPtrIdx, "old_cov");
    SetNoSanitizeMetadata(Counter);
    Value *ToStore = nullptr;

    if (merge_mode == MergeTaint::Add) {
      // Add the current label value to the counter. Untainted is label 0, so
      // this means that for tainted memory this increases coverage.
      ToStore = IRB.CreateAdd(Counter, coverage, "new_cov");
      SetNoSanitizeMetadata(ToStore);
    } else {
      assert(merge_mode == MergeTaint::Or);
      // Just or-in the label which is either 0 (no coverage and no taint)
      // or non-zero (coverage and taint).
      ToStore = IRB.CreateOr(Counter, coverage, "new_cov");
      SetNoSanitizeMetadata(ToStore);
    }

    // Store the updated coverage back to the map so AFL++ sees it.
    StoreInst *StoreCtx = IRB.CreateStore(ToStore, TypedMapPtrIdx, "store_cov");
    SetNoSanitizeMetadata(StoreCtx);
  }

  // Whether this condition is part of a vector of conditions.
  // Used so we can omit the 'not executed' case when saving coverage.
  // (see below).
  enum class IsPartOfConditionVec {
    Yes,
    No
  };

  void addConditionToCoverageMap(IRBuilder<> &IRB, MapElementOffset mapOffset,
                                 Value *condition_raw,
                                 IsPartOfConditionVec partOfConditionVec
                                   = IsPartOfConditionVec::No) {
    // Each condition only needs one byte to represent all values. This way
    // we can squeeze 4 conditions into one 4 byte slot.
    Value *condition = IRB.CreateZExtOrTrunc(condition_raw, Int8Ty);

    // If this is part of a condition vector, we don't need to do the extra
    // operation below for any but the first condition to convey the 'executed'
    // case. The first condition takes care of this.
    if (partOfConditionVec == IsPartOfConditionVec::Yes) {
      addToCoverageMap(IRB, mapOffset, condition, MergeTaint::Or);
      return;
    }


    // Add one to the condition so that the coverage point has the
    // following meanings:
    // 0 -> not executed.
    // 1 -> false branch taken.
    // 2 -> true branch taken.
    // This way the fuzzer can distinguish between those three cases. Without
    // this the fuzzer would see the same coverage for not executed and 'false'.
    Value *condition_non_zero = 
      IRB.CreateAdd(condition, ConstantInt::get(Int8Ty, 1));
    SetNoSanitizeMetadata(condition_non_zero);
    
    addToCoverageMap(IRB, mapOffset, condition_non_zero, MergeTaint::Or);
  }

  void doSelectFeedback(llvm::SelectInst &i, MapElementOffset mapOffset) {
    IRBuilder<> IRB((&i)->getNextNode());

    Value *condition = i.getCondition();
    if (condition->getType()->isIntegerTy()) {
      Value *condition_coverage = IRB.CreateZExtOrTrunc(condition, Int8Ty);
      SetNoSanitizeMetadata(condition_coverage);

      // Add the label to the coverage map.
      addConditionToCoverageMap(IRB, mapOffset, condition_coverage);
      return;
    }

    FixedVectorType *t = cast<FixedVectorType>(condition->getType());
    for (unsigned i = 0; i < t->getNumElements(); ++i) {
      Value *condition_bit = IRB.CreateExtractElement(condition, i);
      SetNoSanitizeMetadata(condition_bit);

      // See implementation of addConditionToCoverageMap for why we
      // special case the first condition and not the others.
      addConditionToCoverageMap(IRB, mapOffset + i, condition_bit,
                                i == 0 ? IsPartOfConditionVec::No :
                                         IsPartOfConditionVec::Yes);
    }
  }

  void doBranchFeedback(llvm::BranchInst &i, MapElementOffset mapOffset) {
    IRBuilder<> IRB(&i);

    Value *condition = i.getCondition();
    if (condition == nullptr)
      exitWithErr("Unconditional edges don't have coverage", condition);

    if (!condition->getType()->isIntegerTy())
      exitWithErr("Branch condition not an integer type?", condition);

    Value *condition_coverage = IRB.CreateZExtOrTrunc(condition, Int8Ty);
    SetNoSanitizeMetadata(condition_coverage);

    // Add the condition value to the coverage map.
    addConditionToCoverageMap(IRB, mapOffset, condition_coverage);
  }

  void doBBFeedback(llvm::Instruction &i, MapElementOffset mapOffset) {
    IRBuilder<> IRB(&i);

    Value *condition_coverage = ConstantInt::get(Int8Ty, 1);
    SetNoSanitizeMetadata(condition_coverage);

    addToCoverageMap(IRB, mapOffset, condition_coverage, MergeTaint::Or);
  }

  void doTaintFeedback(llvm::Instruction &i, MapElementOffset mapOffset) {
    if (!providesFeedback(i)) {
      exitWithErr("Called on bogus non-taint instruction? ", i);
    }

    // Find the pointer that we want to check the taint value for.
    // For load/stores it's just the pointer where the value is stored/loaded
    // from/to.
    Value *ptr = nullptr;
    if (auto *load = dyn_cast<LoadInst>(&i)) {
      ptr = load->getPointerOperand();
    } else if (auto *store = dyn_cast<StoreInst>(&i)) {
      ptr = store->getPointerOperand();
    } else
      exitWithErr("Called on bogus instruction? ", i);

    if (!ptr->getType()->isPointerTy()) {
      llvm::errs() << "Not a pointer type?" << *ptr;
      std::abort();
    }

    // Add taint instrumentation after the load/store.
    // We do it after so that we can read the value taint for stores.
    IRBuilder<> IRB((&i)->getNextNode());

    // Calculate the shadow address of the loaded/store pointer.
    Value *OffsetLong = IRB.CreatePointerCast(ptr, IntptrTy);
    SetNoSanitizeMetadata(OffsetLong);

    // The XOR mask that maps memory to shadow memory in DFSan/MSan.
    const uint64_t XorMask = 0x500000000000;

    // Map the address we're inspecting to the shadow memory.
    Value *shadowAddr =
        IRB.CreateXor(OffsetLong, ConstantInt::get(IntptrTy, XorMask));
    SetNoSanitizeMetadata(shadowAddr);

    Type *shadowType =
        IntegerType::get(i.getContext(),
                         /*bytes to bits*/ 8 * getBytesForDFSanMemoryOp(i));

    // Cast the shadow address to a proper pointer.
    Value *shadowPtr =
        IRB.CreateIntToPtr(shadowAddr, PointerType::get(i.getContext(), 0));
    SetNoSanitizeMetadata(shadowPtr);

    // Load the shadow value that has the label.
    LoadInst *dfsanLabel = IRB.CreateLoad(shadowType, shadowPtr);
    SetNoSanitizeMetadata(dfsanLabel);

    // Add the label to the coverage map.
    addToCoverageMap(IRB, mapOffset, dfsanLabel, MergeTaint::Or);
  }

  // Adds toggle feedback.
  void doToggleFeedback(llvm::StoreInst &i, unsigned long mapOffset) {
    // Find the pointer that we want to check the taint value for.
    // For load/stores it's just the pointer where the value is stored/loaded
    // from/to.
    Value *ptr = i.getPointerOperand();
    if (!canDoToggleFeedback(i))
      exitWithErr("Bogus toggle feedback inst?", i);

    // Add toggle information for the load/store.
    IRBuilder<> IRB(&i);

    Value *old_value = i.getValueOperand();
    // Load the shadow value that has the label.
    LoadInst *new_value = IRB.CreateLoad(old_value->getType(), ptr);
    SetNoSanitizeMetadata(new_value);

    Value *is_different = IRB.CreateXor(new_value, old_value);
    SetNoSanitizeMetadata(is_different);

    // Toggle to 1 if old/new bits are different and new value is 1.
    Value *toggle_to_1 = IRB.CreateAnd(new_value, is_different);
    SetNoSanitizeMetadata(toggle_to_1);

    // Toggle to 0 if old/new bits are different and old value is 1.
    Value *toggle_to_0 = IRB.CreateAnd(old_value, is_different);
    SetNoSanitizeMetadata(toggle_to_0);

    // Add the toggle information to the coverage map.
    addToCoverageMap(IRB, mapOffset, toggle_to_0, MergeTaint::Or);
    addToCoverageMap(IRB, mapOffset + getSlotsForToggleOp(i) / 2, toggle_to_1,
                     MergeTaint::Or);
  }

  /// Finds all coverage points that should be instrumented.
  /// Returns the number of required 4 byte slots in the coverage map.
  unsigned findCoveragePoints(Function &F) {
    toInstrument.clear();
    // The current map offset.
    // Starts at 1 because AFL++ uses the first coverage field to indicate
    // that the function array has been initialized.
    MapElementOffset mapOffset = 1;
    auto queueInstrumentation = [&](DelayedInstrumentation d){
      // Mark which part of the map to use for this instrumentation.
      d.mapPos = mapOffset;

      // Find the next free offset in the map we should use.
      mapOffset += d.requiredMapElements();

      // Schedule for instrumentation after we're done iterating the IR.
      toInstrument.push_back(d);
    };

    for (auto &BB : F) {
      if (isModeOn(CoverageMode::BasicBlock)) {
        DelayedInstrumentation instrumentation;
        instrumentation.blockStart = BB.getFirstNonPHI();
        queueInstrumentation(instrumentation);
      }
      for (auto &I : BB) {
        // Don't touch sanitizer instrumentation.
        if (I.hasMetadata(I.getModule()->getMDKindID("nosanitize")))
          continue;

        // Queue to be instrumented for DFSan/select instrumentation.
        // We can' do this here as we iterate over a list of instructions.
        if (isModeOn(CoverageMode::Taint) && providesFeedback(I)) {
          DelayedInstrumentation instrumentation;
          instrumentation.toInstrumentForDFSan = &I;
          queueInstrumentation(instrumentation);
        }

        // Select instructions behave like coverage blocks.
        if (isModeOn(CoverageMode::Edge) || isModeOn(CoverageMode::BasicBlock)) {
          if (SelectInst *S = dyn_cast<SelectInst>(&I)) {
            DelayedInstrumentation instrumentation;
            instrumentation.selectInst = S;
            queueInstrumentation(instrumentation);
          }
        }

        // Select instructions behave like coverage blocks.
        if (isModeOn(CoverageMode::Edge)) {
          if (BranchInst *B = dyn_cast<BranchInst>(&I)) {
            if (B->isConditional()) {
              DelayedInstrumentation instrumentation;
              instrumentation.branch = B;
              queueInstrumentation(instrumentation);
            }
          }
        }

        if (isModeOn(CoverageMode::Toggle)) {
          if (StoreInst *S = dyn_cast<StoreInst>(&I)) {
            if (S->getValueOperand()->getType()->isIntegerTy()) {
              DelayedInstrumentation instrumentation;
              instrumentation.toggleStore = S;
              queueInstrumentation(instrumentation);
            }
          }
        }
      }
    }

    lastMapSize = mapOffset;
    return lastMapSize;
  }

  void injectCoverage() {
    // Add the feedback for every instruction we found above.
    for (const auto &target : toInstrument) {
      minAllowedMapAccess = target.mapPos;
      maxAllowedMapAccess = target.mapPos + target.requiredMapElements();

      const MapElementOffset mapPos = target.mapPos;

      if (target.toInstrumentForDFSan)
        doTaintFeedback(*target.toInstrumentForDFSan, mapPos);
      else if (target.toggleStore)
        doToggleFeedback(*target.toggleStore, mapPos);
      else if (target.selectInst)
        doSelectFeedback(*target.selectInst, mapPos);
      else if (target.branch)
        doBranchFeedback(*target.branch, mapPos);
      else if (target.blockStart)
        doBBFeedback(*target.blockStart, mapPos);
      else {
        exitWithErr("Not a valid coverage point?");
      }
    }
  }
};

}  // namespace