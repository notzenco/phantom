use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::block::{BasicBlock, BlockId};
use super::instruction::Instruction;
use super::types::{PhysReg, VReg};

/// A backend-applied patch for raw injected function bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RawCodeFixup {
    /// Byte offset within the encoded function body where an 8-byte immediate lives.
    pub offset: u64,
    /// The value source to write at that offset.
    pub target: RawCodeFixupTarget,
}

/// Source for a backend-applied raw code fixup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RawCodeFixupTarget {
    /// The assigned link-time address of this function plus `offset`.
    FunctionAddress { offset: u64 },
}

/// A function in the IR — contains an ordered list of basic blocks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub entry_block: BlockId,
    pub blocks: Vec<BasicBlock>,
    pub vreg_map: HashMap<VReg, PhysReg>,
    pub next_vreg: u32,
    pub raw_fixups: Vec<RawCodeFixup>,
}

impl Function {
    /// Create a new empty function.
    pub fn new(name: String, address: u64, size: u64) -> Self {
        Self {
            name,
            address,
            size,
            entry_block: BlockId(0),
            blocks: Vec::new(),
            vreg_map: HashMap::new(),
            next_vreg: 0,
            raw_fixups: Vec::new(),
        }
    }

    /// Iterate over all instructions across all blocks.
    pub fn instructions(&self) -> impl Iterator<Item = &Instruction> {
        self.blocks.iter().flat_map(|b| b.instructions.iter())
    }

    /// Iterate mutably over all instructions across all blocks.
    pub fn instructions_mut(&mut self) -> impl Iterator<Item = &mut Instruction> {
        self.blocks.iter_mut().flat_map(|b| b.instructions.iter_mut())
    }

    /// Look up a block by its `BlockId`.
    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.iter().find(|b| b.id == id)
    }

    /// Look up a block mutably by its `BlockId`.
    pub fn block_mut(&mut self, id: BlockId) -> Option<&mut BasicBlock> {
        self.blocks.iter_mut().find(|b| b.id == id)
    }

    /// Allocate a fresh virtual register mapped to the given physical register.
    pub fn alloc_vreg(&mut self, phys: PhysReg) -> VReg {
        let vreg = VReg(self.next_vreg);
        self.vreg_map.insert(vreg, phys);
        self.next_vreg += 1;
        vreg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_new_defaults() {
        let f = Function::new("main".into(), 0x401000, 100);
        assert_eq!(f.name, "main");
        assert_eq!(f.address, 0x401000);
        assert_eq!(f.size, 100);
        assert_eq!(f.entry_block, BlockId(0));
        assert!(f.blocks.is_empty());
        assert!(f.vreg_map.is_empty());
        assert_eq!(f.next_vreg, 0);
        assert!(f.raw_fixups.is_empty());
    }

    #[test]
    fn alloc_vreg_increments() {
        let mut f = Function::new("test".into(), 0, 0);
        let v0 = f.alloc_vreg(PhysReg(0));
        let v1 = f.alloc_vreg(PhysReg(1));
        let v2 = f.alloc_vreg(PhysReg(2));

        assert_eq!(v0, VReg(0));
        assert_eq!(v1, VReg(1));
        assert_eq!(v2, VReg(2));
        assert_eq!(f.next_vreg, 3);
        assert_eq!(f.vreg_map[&v0], PhysReg(0));
        assert_eq!(f.vreg_map[&v1], PhysReg(1));
        assert_eq!(f.vreg_map[&v2], PhysReg(2));
    }

    #[test]
    fn block_lookup() {
        use crate::ir::block::Terminator;

        let mut f = Function::new("f".into(), 0, 0);
        f.blocks.push(BasicBlock {
            id: BlockId(0),
            start_addr: 0,
            end_addr: 10,
            instructions: vec![],
            terminator: Terminator::Return,
        });
        f.blocks.push(BasicBlock {
            id: BlockId(1),
            start_addr: 10,
            end_addr: 20,
            instructions: vec![],
            terminator: Terminator::Unreachable,
        });

        assert!(f.block(BlockId(0)).is_some());
        assert!(f.block(BlockId(1)).is_some());
        assert!(f.block(BlockId(99)).is_none());
    }
}
